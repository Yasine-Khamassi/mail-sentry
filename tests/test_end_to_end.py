from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from mail_sentry.analyzer import analyze
from mail_sentry.config import load_rules
from mail_sentry.scoring import score_signals

ROOT = Path(__file__).resolve().parents[1]


def write_eml(directory: str, name: str, content: bytes) -> Path:
    path = Path(directory) / name
    path.write_bytes(content)
    return path


class ScoringTests(unittest.TestCase):
    def test_rule_weight_counts_once_with_all_evidence(self):
        signals = [{"rule": "shortener", "detail": "d", "evidence": f"e{i}"} for i in range(8)]
        score, verdict, weighted = score_signals(signals, load_rules())
        self.assertEqual(score, load_rules()["weights"]["shortener"])
        self.assertEqual(weighted[0]["count"], 8)
        self.assertEqual(len(weighted[0]["evidence"]), 5)
        self.assertEqual(verdict, "low_risk")

    def test_many_tracking_links_stay_low_risk(self):
        links = "".join(f'<a href="https://click.news.example/t?id={i}&u=https%3A%2F%2Fshop.example%2Fp{i}">Item {i}</a>' for i in range(40))
        raw = ("From: Shop <news@shop.example>\nReturn-Path: <bounce@esp.example>\nSubject: Weekly picks\n"
               "Content-Type: text/html; charset=utf-8\n\n" + links).encode()
        with tempfile.TemporaryDirectory() as directory:
            result = analyze(write_eml(directory, "news.eml", raw))
        self.assertEqual(result["verdict"], "low_risk")


class ConfigTests(unittest.TestCase):
    def test_partial_rules_file_merges_with_defaults(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "tenant.json"
            path.write_text(json.dumps({"trusted_authserv_ids": ["mx.corp.example"], "weights": {"shortener": 1}}), encoding="utf-8")
            rules = load_rules(str(path))
        self.assertEqual(rules["weights"]["shortener"], 1)
        self.assertEqual(rules["weights"]["credential_form"], 28)
        self.assertEqual(rules["trusted_authserv_ids"], ["mx.corp.example"])
        self.assertEqual(rules["limits"]["max_urls"], 500)

    def test_bad_rules_file_is_a_value_error(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.json"
            path.write_text("[1, 2]", encoding="utf-8")
            with self.assertRaises(ValueError):
                load_rules(str(path))


class MimeTests(unittest.TestCase):
    def test_unnamed_binary_part_is_treated_as_attachment(self):
        raw = (b"From: a@x.example\nContent-Type: multipart/mixed; boundary=b\n\n--b\nContent-Type: text/plain\n\nhi\n"
               b"--b\nContent-Type: application/octet-stream\nContent-Transfer-Encoding: base64\n\nTVqQAAMAAAAEAAAA\n--b--\n")
        with tempfile.TemporaryDirectory() as directory:
            result = analyze(write_eml(directory, "m.eml", raw))
        self.assertEqual(result["attachments"][0]["detected_type"], "pe")

    def test_html_file_attachment_is_not_merged_into_body(self):
        raw = (b"From: a@x.example\nContent-Type: multipart/mixed; boundary=b\n\n--b\nContent-Type: text/plain\n\nSee file\n"
               b"--b\nContent-Type: text/html\nContent-Disposition: attachment; filename=\"pay.html\"\n\n<input type=password>\n--b--\n")
        with tempfile.TemporaryDirectory() as directory:
            result = analyze(write_eml(directory, "m.eml", raw))
        self.assertEqual(result["attachments"][0]["filename"], "pay.html")
        self.assertIn("html_attachment", [s["rule"] for s in result["signals"]])

    def test_rfc2231_encoded_filename(self):
        raw = (b"From: a@x.example\nContent-Type: multipart/mixed; boundary=b\n\n--b\nContent-Type: text/plain\n\nhi\n"
               b"--b\nContent-Type: application/octet-stream\nContent-Disposition: attachment; filename*=utf-8''facture%2Epdf%2Eexe\n\nMZ\n--b--\n")
        with tempfile.TemporaryDirectory() as directory:
            result = analyze(write_eml(directory, "m.eml", raw))
        self.assertEqual(result["attachments"][0]["filename"], "facture.pdf.exe")
        self.assertIn("double_extension", [s["rule"] for s in result["signals"]])

    def test_broken_boundary_is_reported_as_defect(self):
        raw = b"From: a@x.example\nContent-Type: multipart/mixed; boundary=zz\n\n--wrong\nContent-Type: text/html\n\n<a href='http://x.example'>x</a>\n--wrong--\n"
        with tempfile.TemporaryDirectory() as directory:
            result = analyze(write_eml(directory, "m.eml", raw))
        self.assertTrue(result["parse_defects"])

    def test_binary_blob_declared_as_text_is_handled(self):
        raw = b"From: a@x.example\nContent-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: base64\n\n!!!notbase64%%%\x00\xff\xfe\n"
        with tempfile.TemporaryDirectory() as directory:
            result = analyze(write_eml(directory, "m.eml", raw))
        self.assertEqual(result["verdict"], "low_risk")

    def test_attached_message_is_noted(self):
        raw = (b"From: a@x.example\nContent-Type: multipart/mixed; boundary=b\n\n--b\nContent-Type: text/plain\n\nfwd\n"
               b"--b\nContent-Type: message/rfc822\n\nFrom: inner@y.example\nSubject: inner\n\ninner body\n--b--\n")
        with tempfile.TemporaryDirectory() as directory:
            result = analyze(write_eml(directory, "m.eml", raw))
        self.assertTrue(any("attached message" in note for note in result["analysis_notes"]))

    def test_body_text_limit(self):
        rules = load_rules()
        rules["limits"]["max_text_chars"] = 100
        raw = b"From: a@x.example\nContent-Type: text/plain\n\n" + b"a" * 500 + b" pay now"
        with tempfile.TemporaryDirectory() as directory:
            result = analyze(write_eml(directory, "m.eml", raw), rules)
        self.assertNotIn("payment_lure", [s["rule"] for s in result["signals"]])
        self.assertTrue(any("not analyzed" in note for note in result["analysis_notes"]))


class CliTests(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run([sys.executable, "-m", "mail_sentry.cli", *args], capture_output=True, text=True, encoding="utf-8")

    def test_sample_report_is_json(self):
        completed = self.run_cli(str(ROOT / "samples" / "phishing.eml"))
        self.assertEqual(completed.returncode, 0)
        report = json.loads(completed.stdout)
        self.assertEqual(report["schema_version"], "2.0")

    def test_missing_file_exits_two(self):
        completed = self.run_cli(str(ROOT / "samples" / "missing.eml"))
        self.assertEqual(completed.returncode, 2)
        self.assertIn("mail-sentry:", completed.stderr)


if __name__ == "__main__":
    unittest.main()
