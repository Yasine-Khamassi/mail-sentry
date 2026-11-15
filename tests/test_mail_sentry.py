from __future__ import annotations

import io
import importlib.util
import json
import tempfile
import unittest
import zipfile
import sys
import types
from email.message import EmailMessage, Message
from pathlib import Path
from unittest.mock import patch

from mail_sentry.analyzer import analyze
from mail_sentry.attachment_analysis import analyze_attachment
from mail_sentry.config import load_rules, validate_rules
from mail_sentry.header_analysis import analyze_headers
from mail_sentry.parsing import _normalize_msg, decode_text, iter_parts
from mail_sentry.url_analysis import analyze_urls
from email import policy
from email.parser import BytesParser


ROOT = Path(__file__).resolve().parents[1]


class RulesTests(unittest.TestCase):
    def test_defaults_load_and_fill_limits(self):
        rules = load_rules()
        self.assertEqual(rules["limits"]["max_input_bytes"], 25_000_000)
        self.assertEqual(rules["trusted_authserv_ids"], [])

    def test_rejects_invalid_threshold_order(self):
        with self.assertRaisesRegex(ValueError, "thresholds must be ordered"):
            validate_rules({"thresholds": {"suspicious": 70, "likely_phishing": 40, "high_confidence": 80}})

    def test_rejects_invalid_domain_age_hint(self):
        with self.assertRaisesRegex(ValueError, "age_days"):
            validate_rules({"domain_hints": {"bad.example": {"age_days": -1}}})


class HeaderTests(unittest.TestCase):
    def parse(self, authserv: str) -> object:
        raw = f"From: exec@corp.example\nReturn-Path: bounce@other.example\nAuthentication-Results: {authserv}; spf=fail; dkim=pass\n\nhello".encode()
        return BytesParser(policy=policy.default).parsebytes(raw)

    def test_authentication_claim_untrusted_by_default(self):
        details, signals = analyze_headers(self.parse("mx.corp.example"), {"trusted_authserv_ids": []})
        self.assertEqual(details["authentication"], [])
        self.assertNotIn("auth_fail", [signal["rule"] for signal in signals])

    def test_only_configured_authserv_is_scored(self):
        message = self.parse("mx.corp.example")
        details, signals = analyze_headers(message, {"trusted_authserv_ids": ["mx.corp.example"]})
        self.assertEqual(details["authentication"][0]["result"], "fail")
        self.assertIn("auth_fail", [signal["rule"] for signal in signals])

    def test_empty_authserv_id_is_ignored(self):
        message = BytesParser(policy=policy.default).parsebytes(b"Authentication-Results: ; dmarc=fail\n\nbody")
        details, signals = analyze_headers(message, {"trusted_authserv_ids": ["mx.corp.example"]})
        self.assertEqual(details["authentication"], [])
        self.assertNotIn("auth_fail", [signal["rule"] for signal in signals])

    def test_address_like_text_in_display_name_does_not_set_domain(self):
        message = BytesParser(policy=policy.default).parsebytes(b'From: "ceo@brand.example" <nobody@corp.example>\nReturn-Path: <bounce@other.example>\n\nbody')
        _details, signals = analyze_headers(message, {"trusted_authserv_ids": []})
        self.assertIn("sender_mismatch", [signal["rule"] for signal in signals])


class URLTests(unittest.TestCase):
    def test_nested_redirect_wrapper_is_decoded_without_fetching(self):
        rules = load_rules()
        result, signals = analyze_urls([("https://relay.example/go?url=https%3A%2F%2Fbad.example%2Flogin", "anchor")], "", rules)
        self.assertEqual(result[0]["wrapped_targets"], ["https://bad.example/login"])
        self.assertIn("wrapper link names another URL", result[0]["flags"])
        self.assertEqual(result[1]["context"], "wrapped_target")
        self.assertFalse(any("redirect" in signal["rule"] for signal in signals))

    def test_local_domain_age_hints_add_explainable_signal(self):
        rules = load_rules()
        rules["domain_hints"] = {"brand-login.example": {"age_days": 4, "source": "fixture"}}
        result, signals = analyze_urls([("https://brand-login.example/login", "anchor")], "", rules)
        self.assertEqual(result[0]["domain_age"]["age_days"], 4)
        self.assertIn("new_domain", [signal["rule"] for signal in signals])

    def test_malformed_url_does_not_crash(self):
        result, _ = analyze_urls([("http://[invalid", "anchor")], "", load_rules())
        self.assertEqual(result, [])


class AttachmentTests(unittest.TestCase):
    def test_attachment_size_limit_skips_hashing_and_scan(self):
        rules = load_rules()
        rules["limits"]["max_attachment_bytes"] = 4
        report, signals = analyze_attachment("large.bin", "application/octet-stream", b"12345", rules)
        self.assertIsNone(report["sha256"])
        self.assertIn("inspection skipped", report["flags"][0])
        self.assertEqual(signals, [])

    def test_oversized_attachment_still_scores_extension_metadata(self):
        rules = load_rules()
        rules["limits"]["max_attachment_bytes"] = 4
        report, signals = analyze_attachment("invoice.pdf.exe", "application/octet-stream", b"12345", rules)
        self.assertIn("dangerous file type", report["flags"])
        self.assertIn("double extension", report["flags"])
        self.assertEqual({signal["rule"] for signal in signals}, {"dangerous_attachment", "double_extension"})

    def test_double_extension_reported(self):
        report, signals = analyze_attachment("invoice.pdf.exe", "application/octet-stream", b"MZ", load_rules())
        self.assertIn("double extension", report["flags"])
        self.assertIn("double_extension", [signal["rule"] for signal in signals])

    def test_office_archive_member_urls_are_extracted(self):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("word/document.xml", '<w:t>https://click.example/login</w:t>')
        report, signals = analyze_attachment("letter.docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", stream.getvalue(), load_rules())
        self.assertIn("embedded URL strings", report["flags"])
        self.assertIn("embedded_attachment_url", [signal["rule"] for signal in signals])

    def test_archive_expansion_is_bounded(self):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("word/document.xml", "x" * 20_000)
        rules = load_rules()
        rules["limits"]["max_archive_uncompressed_bytes"] = 100
        report, _ = analyze_attachment("letter.docx", "application/zip", stream.getvalue(), rules)
        self.assertIn("archive inspection limit reached", report["flags"])

    def test_7z_encryption_is_reported_as_unsupported_not_guessed(self):
        report, signals = analyze_attachment("bundle.7z", "application/x-7z-compressed", b"7z\xbc\xaf\x27\x1c" + b"\xff" * 20, load_rules())
        self.assertIn("archive encryption status not inspected for this format", report["flags"])
        self.assertNotIn("encrypted_archive", [signal["rule"] for signal in signals])


class EndToEndTests(unittest.TestCase):
    def test_samples_have_expected_default_verdicts(self):
        rules = load_rules()
        expected = {"clean.eml": (0, "low_risk"), "suspicious.eml": (35, "suspicious"), "phishing.eml": (100, "high_confidence_phishing")}
        for name, verdict in expected.items():
            with self.subTest(name=name):
                result = analyze(ROOT / "samples" / name, rules)
                self.assertEqual((result["score"], result["verdict"]), verdict)
                json.dumps(result)

    def test_input_size_limit_is_enforced_before_parsing(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "large.eml"
            path.write_bytes(b"Subject: x\n\n" + b"x" * 20)
            rules = load_rules()
            rules["limits"]["max_input_bytes"] = 10
            with self.assertRaisesRegex(ValueError, "exceeds configured limit"):
                analyze(path, rules)

    def test_forged_authentication_header_has_no_default_score(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "forged.eml"
            path.write_text("From: user@example.com\nAuthentication-Results: fake.example; spf=fail; dkim=fail; dmarc=fail\n\nHi", encoding="utf-8")
            result = analyze(path)
            self.assertEqual(result["message"]["authentication"], [])
            self.assertNotIn("auth_fail", [signal["rule"] for signal in result["signals"]])

    def test_msg_uses_extract_msg_email_conversion_and_closes_handle(self):
        instances = []

        class FakeMsg:
            def __init__(self, _path):
                self.closed = False
                instances.append(self)
                self.header = Message()
                self.header["Subject"] = "Shared document requires review"
                self.header["From"] = "Sender <sender@corp.example>"
                self.header["To"] = "Analyst <analyst@corp.example>"
                self.body = "Please see the attached file."
                self.htmlBody = b'<p>Review the shared document.</p><a href="https://click.example/login">Open</a>'
                self.attachments = [object()]

            def asEmailMessage(self):
                normalized = EmailMessage()
                normalized["Subject"] = self.header["Subject"]
                normalized["From"] = self.header["From"]
                normalized["To"] = self.header["To"]
                normalized.set_content(self.body)
                normalized.add_alternative(self.htmlBody.decode("utf-8"), subtype="html")
                normalized.add_attachment(b"MZpayload", maintype="application", subtype="octet-stream", filename="invoice.pdf.exe")
                return normalized

            def close(self):
                self.closed = True

        fake_module = types.ModuleType("extract_msg")
        fake_module.Message = FakeMsg
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "message.msg"
            path.write_bytes(b"mock MSG container")
            with patch.dict(sys.modules, {"extract_msg": fake_module}):
                result = analyze(path)
        self.assertTrue(instances[0].closed)
        self.assertEqual(result["message"]["subject"], "Shared document requires review")
        self.assertEqual(result["attachments"][0]["filename"], "invoice.pdf.exe")
        self.assertIn("double_extension", [signal["rule"] for signal in result["signals"]])
        self.assertEqual(result["urls"][0]["host"], "click.example")

    def test_msg_conversion_error_still_closes_handle(self):
        instances = []

        class FakeMsg:
            def __init__(self, _path):
                self.closed = False
                instances.append(self)
                self.header = Message()
                self.header["Subject"] = "Attachment inspection"
                self.header["From"] = "sender@example.test"
                self.body = "See attached."
                self.htmlBody = b"<p>See attached.</p>"
                self.attachments = [types.SimpleNamespace(data=b"MZ", longFilename="report.exe", mimetype="application/octet-stream")]

            def asEmailMessage(self):
                raise RuntimeError("conversion failed")

            def close(self):
                self.closed = True

        fake_module = types.ModuleType("extract_msg")
        fake_module.Message = FakeMsg
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fallback.msg"
            path.write_bytes(b"mock MSG container")
            with patch.dict(sys.modules, {"extract_msg": fake_module}):
                result = analyze(path)
        self.assertTrue(instances[0].closed)
        self.assertEqual(result["attachments"][0]["filename"], "report.exe")
        self.assertIn("dangerous_attachment", [signal["rule"] for signal in result["signals"]])


class ParsingTests(unittest.TestCase):
    def test_unknown_charset_falls_back_to_utf8(self):
        class InvalidCharsetPart(Message):
            def get_content(self):
                raise LookupError("unknown charset")

            def get_payload(self, decode=False):
                return b"hello \xff" if decode else ""

            def get_content_charset(self):
                return "x-not-a-real-codec"

        part = InvalidCharsetPart()
        self.assertEqual(decode_text(part), "hello \ufffd")

    def test_mime_part_limit_is_enforced_iteratively(self):
        root = Message()
        current = root
        for _ in range(20):
            child = Message()
            current.set_payload([child])
            current = child
        with self.assertRaisesRegex(ValueError, "MIME part limit"):
            list(iter_parts(root, 10))


@unittest.skipUnless(importlib.util.find_spec("extract_msg"), "optional extract-msg package is not installed")
class ExtractMsgApiTests(unittest.TestCase):
    def test_installed_public_conversion_api_preserves_bodies_and_attachments(self):
        import extract_msg

        class Attachment:
            dataType = bytes
            data = b"MZpayload"
            mimetype = "application/octet-stream"
            contentId = None
            hidden = False
            name = "proof.exe"

            def getFilename(self):
                return self.name

        class MsgShape:
            header = EmailMessage()
            headerText = None
            body = "Plain body"
            htmlBody = b"<p>HTML body</p>"
            attachments = [Attachment()]

            def asEmailMessage(self):
                return extract_msg.Message.asEmailMessage(self)

        MsgShape.header["Subject"] = "API conversion"
        normalized = _normalize_msg(MsgShape())
        self.assertEqual(normalized["Subject"], "API conversion")
        parts = list(iter_parts(normalized, 20))
        self.assertTrue(any(part.get_content_type() == "text/plain" for part in parts))
        self.assertTrue(any(part.get_content_type() == "text/html" for part in parts))
        self.assertTrue(any(part.get_filename() == "proof.exe" for part in parts))


if __name__ == "__main__":
    unittest.main()
