from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from email import policy
from email.parser import BytesParser
from pathlib import Path

from mail_sentry.analyzer import analyze
from mail_sentry.auth_verification import check_spf, connecting_client, verify_authentication
from mail_sentry.config import load_rules
from mail_sentry.resolver import OfflineResolver, StaticResolver

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "auth"
HAS_DKIM = importlib.util.find_spec("dkim") is not None
HAS_SPF = importlib.util.find_spec("spf") is not None
GATEWAY = b"Received: from out.signer.example (out.signer.example [192.0.2.10]) by mx.corp.example with ESMTPS id 1;\r\n Mon, 09 Nov 2026 10:03:05 +0000\r\n"


def dkim_records() -> dict:
    return json.loads((FIXTURES / "dkim_records.json").read_text(encoding="utf-8"))


def parse(raw: bytes):
    return BytesParser(policy=policy.default).parsebytes(raw)


def gateway_rules():
    rules = load_rules()
    rules["trusted_receivers"] = ["mx.corp.example"]
    return rules


def run(raw: bytes, records: dict | None = None, check_spf_enabled: bool = False, rules: dict | None = None):
    resolver = StaticResolver(records) if records is not None else OfflineResolver()
    return verify_authentication(parse(raw), raw, rules or gateway_rules(), resolver, check_spf_enabled)


def rule_names(signals):
    return {signal["rule"] for signal in signals}


@unittest.skipUnless(HAS_DKIM, "dkimpy not installed")
class DkimTests(unittest.TestCase):
    def test_valid_signature_passes(self):
        auth, signals = run((FIXTURES / "dkim_signed.eml").read_bytes(), dkim_records())
        self.assertEqual(auth["dkim"]["result"], "pass")
        self.assertTrue(auth["dkim"]["verified"])
        self.assertEqual((auth["dkim"]["d_tag"], auth["dkim"]["s_tag"]), ("signer.example", "sel1"))
        self.assertNotIn("dkim_fail", rule_names(signals))

    def test_tampered_body_fails(self):
        auth, signals = run((FIXTURES / "dkim_tampered.eml").read_bytes(), dkim_records())
        self.assertEqual(auth["dkim"]["result"], "fail")
        self.assertIn("body hash mismatch", auth["dkim"]["errors"][0])
        self.assertIn("dkim_fail", rule_names(signals))

    def test_tampered_header_fails(self):
        raw = (FIXTURES / "dkim_signed.eml").read_bytes().replace(b"Subject: Your November statement", b"Subject: Your December statement")
        auth, _signals = run(raw, dkim_records())
        self.assertEqual(auth["dkim"]["result"], "fail")

    def test_missing_key_is_permerror_not_a_crash(self):
        auth, signals = run((FIXTURES / "dkim_signed.eml").read_bytes(), {})
        self.assertEqual(auth["dkim"]["result"], "permerror")
        self.assertFalse(auth["dkim"]["verified"])
        self.assertIn("no DKIM key record", auth["dkim"]["errors"][0])
        self.assertNotIn("dkim_fail", rule_names(signals))

    def test_dns_failure_is_temperror(self):
        auth, _signals = run((FIXTURES / "dkim_signed.eml").read_bytes(), {"sel1._domainkey.signer.example": {"TXT": "TEMPFAIL"}})
        self.assertEqual(auth["dkim"]["result"], "temperror")
        self.assertFalse(auth["dkim"]["verified"])

    def test_bad_key_record_is_permerror(self):
        auth, _signals = run((FIXTURES / "dkim_signed.eml").read_bytes(), {"sel1._domainkey.signer.example": {"TXT": ["v=DKIM1; k=rsa; p=bm90IGEga2V5"]}})
        self.assertEqual(auth["dkim"]["result"], "permerror")

    def test_offline_default_does_not_look_up_keys(self):
        auth, signals = run((FIXTURES / "dkim_signed.eml").read_bytes())
        self.assertEqual(auth["dkim"]["result"], "neutral")
        self.assertIn("DNS is disabled", auth["dkim"]["errors"][0])
        self.assertEqual(signals, [])

    def test_unsigned_message_is_none(self):
        auth, _signals = run(b"From: a@x.example\r\n\r\nhi\r\n")
        self.assertEqual(auth["dkim"]["result"], "none")

    def test_malformed_signature_is_permerror(self):
        auth, _signals = run(b"DKIM-Signature: v=1; d=x.example; garbage\r\nFrom: a@x.example\r\n\r\nhi\r\n", {})
        self.assertEqual(auth["dkim"]["result"], "permerror")


@unittest.skipUnless(HAS_SPF, "pyspf not installed")
class SpfTests(unittest.TestCase):
    MESSAGE = (b"Received: by mx.corp.example with LMTP id 2;\r\n Mon, 09 Nov 2026 10:03:06 +0000\r\n" + GATEWAY
               + b"Received: from laptop (unknown [198.51.100.7]) by out.signer.example;\r\n Mon, 09 Nov 2026 10:03:01 +0000\r\n"
               + b"Return-Path: <bounce@signer.example>\r\nFrom: billing@signer.example\r\n\r\nhi\r\n")

    def spf(self, record: str):
        resolver = StaticResolver({"signer.example": {"TXT": [record]}})
        return check_spf(parse(self.MESSAGE), gateway_rules(), resolver, True)

    def test_connecting_client_is_the_first_untrusted_hop(self):
        hop, note = connecting_client(parse(self.MESSAGE), gateway_rules())
        self.assertEqual(hop, {"ip": "192.0.2.10", "helo": "out.signer.example"})
        self.assertEqual(note, "")

    def test_pass(self):
        report = self.spf("v=spf1 ip4:192.0.2.0/24 -all")
        self.assertEqual((report["result"], report["ip"], report["from"]), ("pass", "192.0.2.10", "bounce@signer.example"))

    def test_fail(self):
        self.assertEqual(self.spf("v=spf1 ip4:203.0.113.0/24 -all")["result"], "fail")

    def test_softfail(self):
        self.assertEqual(self.spf("v=spf1 ip4:203.0.113.0/24 ~all")["result"], "softfail")

    def test_neutral(self):
        self.assertEqual(self.spf("v=spf1 ?all")["result"], "neutral")

    def test_permerror_for_broken_record(self):
        self.assertEqual(self.spf("v=spf1 ip4:not-an-ip -all")["result"], "permerror")

    def test_none_without_record(self):
        report = check_spf(parse(self.MESSAGE), gateway_rules(), StaticResolver({}), True)
        self.assertEqual(report["result"], "none")

    def test_temperror(self):
        report = check_spf(parse(self.MESSAGE), gateway_rules(), StaticResolver({"signer.example": {"TXT": "TEMPFAIL"}}), True)
        self.assertEqual(report["result"], "temperror")

    def test_off_by_default(self):
        report = check_spf(parse(self.MESSAGE), gateway_rules(), StaticResolver({}), False)
        self.assertIsNone(report["result"])
        self.assertFalse(report["checked"])

    def test_spf_fail_signal(self):
        resolver = StaticResolver({"signer.example": {"TXT": ["v=spf1 -all"]}})
        _auth, signals = verify_authentication(parse(self.MESSAGE), self.MESSAGE, gateway_rules(), resolver, True)
        self.assertIn("spf_fail", rule_names(signals))

    def test_without_trusted_receivers_topmost_hop_is_used_and_noted(self):
        raw = GATEWAY + b"From: a@signer.example\r\n\r\nhi\r\n"
        hop, note = connecting_client(parse(raw), load_rules())
        self.assertEqual(hop["ip"], "192.0.2.10")
        self.assertIn("no trusted_receivers configured", note)

    def test_ipv6_client(self):
        raw = b"Received: from v6.signer.example ([IPv6:2001:db8::25]) by mx.corp.example;\r\n Mon, 09 Nov 2026 10:03:05 +0000\r\nFrom: a@signer.example\r\n\r\nhi\r\n"
        hop, _note = connecting_client(parse(raw), gateway_rules())
        self.assertEqual(hop["ip"], "2001:db8::25")


@unittest.skipUnless(HAS_DKIM and HAS_SPF, "dkimpy and pyspf not installed")
class DmarcTests(unittest.TestCase):
    def records(self, spf_record="v=spf1 -all", dmarc="v=DMARC1; p=reject"):
        records = dkim_records()
        records["signer.example"] = {"TXT": [spf_record]}
        records["_dmarc.signer.example"] = {"TXT": [dmarc]}
        return records

    def signed(self, name="dkim_signed.eml", return_path=b"bounce@signer.example"):
        return GATEWAY + b"Return-Path: <" + return_path + b">\r\n" + (FIXTURES / name).read_bytes()

    def test_aligned_dkim_pass_gives_dmarc_pass(self):
        auth, signals = run(self.signed(), self.records(), check_spf_enabled=True)
        self.assertEqual(auth["dmarc"]["result"], "pass")
        self.assertEqual(auth["dmarc"]["policy"], "reject")
        self.assertTrue(auth["dmarc"]["alignment"]["dkim"])
        self.assertFalse(auth["dmarc"]["alignment"]["spf"])
        self.assertNotIn("dmarc_fail", rule_names(signals))

    def test_aligned_spf_pass_alone_gives_dmarc_pass(self):
        auth, _signals = run(self.signed("dkim_tampered.eml"), self.records("v=spf1 ip4:192.0.2.10 -all"), check_spf_enabled=True)
        self.assertEqual(auth["dkim"]["result"], "fail")
        self.assertTrue(auth["dmarc"]["alignment"]["spf"])
        self.assertEqual(auth["dmarc"]["result"], "pass")

    def test_spf_pass_for_unaligned_domain_does_not_count(self):
        records = self.records()
        records["bulk-sender.example"] = {"TXT": ["v=spf1 ip4:192.0.2.10 -all"]}
        auth, signals = run(self.signed("dkim_tampered.eml", b"bounce@bulk-sender.example"), records, check_spf_enabled=True)
        self.assertEqual(auth["spf"]["result"], "pass")
        self.assertFalse(auth["dmarc"]["alignment"]["spf"])
        self.assertEqual(auth["dmarc"]["result"], "fail")
        self.assertIn("dmarc_fail", rule_names(signals))

    def test_dmarc_fail_with_tampered_body_and_spf_fail(self):
        auth, signals = run(self.signed("dkim_tampered.eml"), self.records(), check_spf_enabled=True)
        self.assertEqual(auth["dmarc"]["result"], "fail")
        self.assertEqual({"dkim_fail", "spf_fail", "dmarc_fail"}, rule_names(signals))

    def test_forged_authentication_results_do_not_change_dmarc(self):
        raw = b"Authentication-Results: mx.corp.example; dkim=pass; spf=pass; dmarc=pass\r\n" + self.signed("dkim_tampered.eml")
        rules = gateway_rules()
        rules["trusted_authserv_ids"] = ["mx.corp.example"]
        auth, _signals = run(raw, self.records(), check_spf_enabled=True, rules=rules)
        self.assertEqual(auth["dmarc"]["result"], "fail")

    def test_no_dmarc_record_is_none(self):
        records = self.records()
        del records["_dmarc.signer.example"]
        auth, _signals = run(self.signed(), records, check_spf_enabled=True)
        self.assertEqual(auth["dmarc"]["result"], "none")

    def test_strict_alignment_rejects_parent_domain_signature(self):
        raw = self.signed().replace(b"From: Billing <billing@signer.example>", b"From: Billing <billing@news.signer.example>")
        auth, _signals = run(raw, self.records(dmarc="v=DMARC1; p=quarantine; adkim=s"), check_spf_enabled=True)
        self.assertEqual(auth["dmarc"]["alignment"]["adkim"], "s")
        # From changed, so the signature also breaks; alignment must be false either way.
        self.assertFalse(auth["dmarc"]["alignment"]["dkim"])

    def test_without_spf_check_dmarc_is_not_decided(self):
        auth, _signals = run(self.signed("dkim_tampered.eml"), self.records())
        self.assertEqual(auth["dmarc"]["result"], "neutral")

    def test_dmarc_lookup_failure_is_temperror(self):
        records = self.records()
        records["_dmarc.signer.example"] = {"TXT": "TEMPFAIL"}
        auth, _signals = run(self.signed(), records, check_spf_enabled=True)
        self.assertEqual(auth["dmarc"]["result"], "temperror")

    def test_two_from_addresses_is_permerror(self):
        auth, _signals = run(b"From: a@x.example, b@y.example\r\n\r\nhi\r\n", {})
        self.assertEqual(auth["dmarc"]["result"], "permerror")


class OfflineAnalyzerTests(unittest.TestCase):
    def test_report_has_auth_block_and_stays_offline(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "m.eml"
            path.write_bytes((FIXTURES / "dkim_signed.eml").read_bytes())
            report = analyze(path)
        self.assertEqual(set(report["auth"]), {"dkim", "spf", "dmarc"})
        self.assertIsNone(report["auth"]["spf"]["result"])
        self.assertIn("offline", report["analysis_notes"][0])

    @unittest.skipUnless(HAS_DKIM, "dkimpy not installed")
    def test_analyze_with_static_records(self):
        report = analyze(FIXTURES / "dkim_tampered.eml", resolver=StaticResolver(dkim_records()))
        self.assertEqual(report["auth"]["dkim"]["result"], "fail")
        self.assertIn("dkim_fail", [s["rule"] for s in report["signals"]])


@unittest.skipUnless(HAS_DKIM, "dkimpy not installed")
class CliTests(unittest.TestCase):
    def test_dns_records_flag_verifies_offline(self):
        completed = subprocess.run([sys.executable, "-m", "mail_sentry.cli", str(FIXTURES / "dkim_signed.eml"), "--dns-records", str(FIXTURES / "dkim_records.json")], capture_output=True, text=True, encoding="utf-8")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(json.loads(completed.stdout)["auth"]["dkim"]["result"], "pass")

    def test_bad_dns_records_file_exits_two(self):
        completed = subprocess.run([sys.executable, "-m", "mail_sentry.cli", str(FIXTURES / "dkim_signed.eml"), "--dns-records", str(FIXTURES / "dkim_signed.eml")], capture_output=True, text=True, encoding="utf-8")
        self.assertEqual(completed.returncode, 2)


class ResolverTests(unittest.TestCase):
    def test_static_records_are_validated(self):
        with self.assertRaises(ValueError):
            StaticResolver({"x.example": {"BOGUS": ["1"]}})
        with self.assertRaises(ValueError):
            StaticResolver({"x.example": {"TXT": "nope"}})

    def test_names_are_case_and_dot_insensitive(self):
        resolver = StaticResolver({"X.Example.": {"txt": ["v=spf1 -all"]}})
        self.assertEqual(resolver.query("x.example", "TXT"), ["v=spf1 -all"])


if __name__ == "__main__":
    unittest.main()
