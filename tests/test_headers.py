from __future__ import annotations

import unittest
from email import policy
from email.parser import BytesParser

from mail_sentry.config import load_rules
from mail_sentry.header_analysis import address_domain, analyze_headers


def parse(text: str):
    return BytesParser(policy=policy.default).parsebytes(text.encode("utf-8"))


def rules_with(**overrides):
    rules = load_rules()
    rules.update(overrides)
    return rules


def rule_names(signals):
    return {signal["rule"] for signal in signals}


GATEWAY = rules_with(trusted_authserv_ids=["mx.corp.example"])


class AuthenticationTrustTests(unittest.TestCase):
    def test_result_inside_gateway_block_is_used(self):
        message = parse(
            "Received: by mx.corp.example with ESMTPS id 1\n"
            "Authentication-Results: mx.corp.example; spf=fail smtp.mailfrom=x.example; dmarc=fail\n"
            "Received: from attacker.example by attacker-mta.example\n"
            "From: a@x.example\n\nbody"
        )
        details, signals = analyze_headers(message, GATEWAY)
        self.assertEqual({(a["mechanism"], a["result"]) for a in details["authentication"]}, {("spf", "fail"), ("dmarc", "fail")})
        self.assertIn("auth_fail", rule_names(signals))

    def test_forged_trusted_header_below_boundary_is_ignored(self):
        message = parse(
            "Received: by mx.corp.example with ESMTPS id 1\n"
            "Authentication-Results: mx.corp.example; spf=pass; dkim=pass; dmarc=pass\n"
            "Received: from attacker.example by attacker-mta.example\n"
            "Authentication-Results: mx.corp.example; spf=fail; dmarc=fail\n"
            "From: a@x.example\n\nbody"
        )
        details, signals = analyze_headers(message, GATEWAY)
        self.assertTrue(all(a["result"] == "pass" for a in details["authentication"]))
        self.assertIn("below the trusted receiving boundary", [i["reason"] for i in details["ignored_authentication_results"]])
        self.assertNotIn("auth_fail", rule_names(signals))

    def test_forged_pass_cannot_hide_when_gateway_never_appears(self):
        message = parse(
            "Received: from attacker.example by attacker-mta.example\n"
            "Authentication-Results: mx.corp.example; spf=pass; dmarc=pass\n"
            "From: a@x.example\n\nbody"
        )
        details, _signals = analyze_headers(message, GATEWAY)
        self.assertEqual(details["authentication"], [])

    def test_internal_hop_above_gateway_is_allowed(self):
        message = parse(
            "Received: by 2001:db8::1 with SMTP id internal\n"
            "Received: from out.sender.example by mx.corp.example with ESMTPS\n"
            "Authentication-Results: mx.corp.example; dkim=fail header.d=sender.example\n"
            "Received: from laptop by out.sender.example\n"
            "From: a@sender.example\n\nbody"
        )
        details, signals = analyze_headers(message, GATEWAY)
        self.assertEqual(details["authentication"][0]["result"], "fail")
        self.assertIn("auth_fail", rule_names(signals))

    def test_only_topmost_header_per_authserv_is_used(self):
        message = parse(
            "Authentication-Results: mx.corp.example; dmarc=pass\n"
            "Authentication-Results: mx.corp.example; dmarc=fail\n"
            "Received: by mx.corp.example\n"
            "From: a@x.example\n\nbody"
        )
        details, signals = analyze_headers(message, GATEWAY)
        self.assertEqual([a["result"] for a in details["authentication"]], ["pass"])
        self.assertNotIn("auth_fail", rule_names(signals))

    def test_comments_are_not_parsed_as_results(self):
        message = parse("Authentication-Results: mx.corp.example (spf=fail was a test); spf=pass (dkim=fail old)\nReceived: by mx.corp.example\n\nbody")
        details, _signals = analyze_headers(message, GATEWAY)
        self.assertEqual([(a["mechanism"], a["result"]) for a in details["authentication"]], [("spf", "pass")])

    def test_trusted_receivers_can_differ_from_authserv_id(self):
        rules = rules_with(trusted_authserv_ids=["corp.example"], trusted_receivers=["gw1.corp.example"])
        message = parse("Received: by gw1.corp.example\nAuthentication-Results: corp.example; dmarc=fail\nReceived: by outside.example\n\nbody")
        details, _signals = analyze_headers(message, rules)
        self.assertEqual(details["authentication"][0]["result"], "fail")


class SenderTests(unittest.TestCase):
    def test_subdomains_of_same_organization_do_not_mismatch(self):
        message = parse("From: news@mail.shop.example.co.uk\nReturn-Path: <bounce@bounces.shop.example.co.uk>\nReply-To: help@shop.example.co.uk\n\nbody")
        _details, signals = analyze_headers(message, load_rules())
        self.assertFalse({"sender_mismatch", "reply_to_mismatch"} & rule_names(signals))

    def test_display_name_address_is_not_used_as_sender_domain(self):
        self.assertEqual(address_domain('"ceo@brand.example" <nobody@corp.example>'), "corp.example")

    def test_display_name_with_other_address_is_flagged(self):
        message = parse('From: "ceo@brand.example" <nobody@corp.example>\n\nbody')
        _details, signals = analyze_headers(message, load_rules())
        self.assertIn("display_name_spoof", rule_names(signals))

    def test_encoded_display_name_naming_a_brand_is_flagged(self):
        message = parse("From: =?utf-8?q?PayPal_Service?= <alerts@pp-notify.example>\n\nbody")
        details, signals = analyze_headers(message, load_rules())
        self.assertEqual(details["from_display_name"], "PayPal Service")
        self.assertIn("display_name_spoof", rule_names(signals))

    def test_brand_display_name_from_brand_domain_is_clean(self):
        message = parse("From: Microsoft <account-security-noreply@accountprotection.microsoft.com>\n\nbody")
        _details, signals = analyze_headers(message, load_rules())
        self.assertNotIn("display_name_spoof", rule_names(signals))

    def test_sender_lookalike_domain(self):
        message = parse("From: Support <help@paypa1.example>\n\nbody")
        _details, signals = analyze_headers(message, load_rules())
        self.assertIn("sender_lookalike", rule_names(signals))

    def test_duplicate_from_headers_are_flagged(self):
        message = parse("From: a@one.example\nFrom: b@two.example\n\nbody")
        _details, signals = analyze_headers(message, load_rules())
        self.assertIn("malformed_sender", rule_names(signals))

    def test_group_syntax_and_empty_return_path_do_not_crash(self):
        message = parse("From: undisclosed-recipients:;\nReturn-Path: <>\nTo: Team: a@x.example, b@y.example;\n\nbody")
        details, signals = analyze_headers(message, load_rules())
        self.assertIn("malformed_sender", rule_names(signals))
        self.assertEqual(details["from_address"], "")

    def test_unicode_subject_is_decoded(self):
        message = parse("Subject: =?utf-8?b?w4lsw6l2ZSBkZSBsYSBmYWN0dXJl?=\nFrom: a@x.example\n\nbody")
        details, _signals = analyze_headers(message, load_rules())
        self.assertEqual(details["subject"], chr(0xC9) + "l" + chr(0xE9) + "ve de la facture")


if __name__ == "__main__":
    unittest.main()
