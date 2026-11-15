from __future__ import annotations

import unittest

from mail_sentry.config import load_rules
from mail_sentry.url_analysis import analyze_urls, lookalike, normalize_url, parse_ip_host, registrable_hint

ZWSP = chr(0x200B)
BACKSLASH = chr(92)
TRUSTED = ["microsoft.com", "microsoftonline.com", "paypal.com", "apple.com", "amazon.com", "google.com", "ups.com"]


def rules_of(result_signals):
    return {signal["rule"] for signal in result_signals}


class NormalizationTests(unittest.TestCase):
    def test_host_is_lowercased_and_dot_segments_resolved(self):
        self.assertEqual(normalize_url("HTTPS://Login.Example.COM:443/a/./b/../c//d?x=1#frag")["url"], "https://login.example.com/a/c/d?x=1#frag")

    def test_percent_encoded_host_is_decoded(self):
        self.assertEqual(normalize_url("http://exa%6dple.com/")["host"], "example.com")

    def test_backslashes_and_extra_slashes_are_treated_like_a_browser(self):
        raw = "https:" + BACKSLASH * 2 + "evil.example" + BACKSLASH + "login"
        self.assertEqual(normalize_url(raw)["url"], "https://evil.example/login")
        self.assertEqual(normalize_url("https:///evil.example/x")["host"], "evil.example")

    def test_unicode_host_becomes_punycode_and_ideographic_dots_fold(self):
        host = normalize_url("http://b" + chr(0x00FC) + "cher" + chr(0x3002) + "example/")["host"]
        self.assertEqual(host, "xn--bcher-kva.example")

    def test_invisible_characters_and_tabs_are_removed(self):
        self.assertEqual(normalize_url("https://pay" + ZWSP + "pal.example/\tx")["host"], "paypal.example")

    def test_userinfo_is_reported_separately(self):
        parts = normalize_url("https://microsoft.com@198.51.100.25/secure")
        self.assertEqual(parts["host"], "198.51.100.25")
        self.assertEqual(parts["userinfo"], "microsoft.com")

    def test_invalid_port_returns_none(self):
        self.assertIsNone(normalize_url("http://a.example:99999/"))

    def test_registrable_hint_handles_common_two_label_suffixes(self):
        self.assertEqual(registrable_hint("www.shop.example.co.uk"), "example.co.uk")
        self.assertEqual(registrable_hint("a.b.example.com"), "example.com")


class IpLiteralTests(unittest.TestCase):
    def test_integer_hex_and_octal_ipv4_forms(self):
        self.assertEqual(parse_ip_host("3232235777"), "192.168.1.1")
        self.assertEqual(parse_ip_host("0xc0.0xa8.1.1"), "192.168.1.1")
        self.assertEqual(parse_ip_host("0300.0250.01.01"), "192.168.1.1")
        self.assertEqual(parse_ip_host("[2001:db8::1]"), "2001:db8::1")
        self.assertIsNone(parse_ip_host("example.com"))
        self.assertIsNone(parse_ip_host("1.2.3.4.5"))

    def test_nonstandard_ip_is_flagged(self):
        result, signals = analyze_urls([("http://3232235777/login", "anchor")], "", load_rules())
        self.assertIn("ip_url", rules_of(signals))
        self.assertIn("non-standard", signals[0]["detail"])


class LookalikeTests(unittest.TestCase):
    def test_homoglyph_and_typo_domains_match(self):
        self.assertEqual(lookalike("micros0ft.example", TRUSTED), "microsoft.com")
        self.assertEqual(lookalike("rnicrosoft.example", TRUSTED), "microsoft.com")
        self.assertEqual(lookalike("paypa1.example", TRUSTED), "paypal.com")
        self.assertEqual(lookalike("xn--pple-43d.com", TRUSTED), "apple.com")

    def test_brand_as_separate_token_matches(self):
        self.assertEqual(lookalike("paypal-secure.example", TRUSTED), "paypal.com")
        self.assertEqual(lookalike("ups-delivery.example", TRUSTED), "ups.com")

    def test_brand_owned_and_unrelated_domains_do_not_match(self):
        for host in ("login.microsoftonline.com", "groups.google.com", "amazonaws.com", "applepie.example", "groups.example", "pineapple.example", "upsilon.example"):
            with self.subTest(host=host):
                self.assertIsNone(lookalike(host, TRUSTED))

    def test_mixed_script_punycode_is_described(self):
        _result, signals = analyze_urls([("https://xn--pple-43d.com/", "anchor")], "", load_rules())
        punycode = [s for s in signals if s["rule"] == "punycode_domain"]
        self.assertIn("mixes Latin", punycode[0]["detail"])


class ObfuscationCalibrationTests(unittest.TestCase):
    def test_percent_encoding_in_query_is_not_obfuscation(self):
        _result, signals = analyze_urls([("https://news.example/track?u=a%20b&c=%2Fpath", "anchor")], "", load_rules())
        self.assertNotIn("obfuscated_url", rules_of(signals))

    def test_percent_encoding_in_host_is_obfuscation(self):
        _result, signals = analyze_urls([("http://pay%70al.example/", "anchor")], "", load_rules())
        self.assertIn("obfuscated_url", rules_of(signals))

    def test_data_uri_html_link_is_flagged(self):
        result, signals = analyze_urls([("data:text/html;base64,PGgxPkhpPC9oMT4=", "anchor")], "", load_rules())
        self.assertIn("data_uri_link", rules_of(signals))
        self.assertEqual(result[0]["flags"], ["data URI"])

    def test_mailto_is_ignored(self):
        result, signals = analyze_urls([("mailto:help@example.com", "anchor")], "", load_rules())
        self.assertEqual((result, signals), ([], []))


class WrapperTests(unittest.TestCase):
    def test_fragment_wrapper_is_decoded(self):
        result, _ = analyze_urls([("https://relay.example/#url=https%3A%2F%2Fevil.example%2Fx", "anchor")], "", load_rules())
        self.assertEqual(result[0]["wrapped_targets"], ["https://evil.example/x"])

    def test_wrapper_depth_is_bounded(self):
        rules = load_rules()
        rules["limits"]["max_nested_url_depth"] = 1
        inner = "https%3A%2F%2Fb.example%2F%3Furl%3Dhttps%253A%252F%252Fc.example%252F"
        result, _ = analyze_urls([("https://a.example/?url=" + inner, "anchor")], "", rules)
        self.assertEqual(len(result[0]["wrapped_targets"]), 1)

    def test_url_count_limit_is_enforced(self):
        rules = load_rules()
        rules["limits"]["max_urls"] = 3
        entries = [(f"https://host{i}.example/", "anchor") for i in range(10)]
        result, signals = analyze_urls(entries, "", rules)
        self.assertEqual(len(result), 3)
        self.assertIn("analysis_limit", rules_of(signals))


if __name__ == "__main__":
    unittest.main()
