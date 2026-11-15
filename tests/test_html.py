from __future__ import annotations

import unittest

from mail_sentry.body_analysis import analyze_body

ZWSP = chr(0x200B)
RLO = chr(0x202E)


def rules_of(signals):
    return {signal["rule"] for signal in signals}


class HtmlParsingTests(unittest.TestCase):
    def test_escaped_markup_shown_as_text_is_not_active_content(self):
        # A security bulletin quoting markup must not be read as a live form.
        html = "<p>Example payload: &lt;script&gt;alert(1)&lt;/script&gt; &lt;input type=password&gt;</p>"
        signals, _links, _text = analyze_body("", html)
        self.assertNotIn("script_content", rules_of(signals))
        self.assertNotIn("credential_form", rules_of(signals))

    def test_entity_encoded_attributes_are_decoded(self):
        html = '<a href="java&#115;cript:alert(1)">x</a><input type="pass&#119;ord">'
        signals, _links, _text = analyze_body("", html)
        self.assertIn("script_content", rules_of(signals))
        self.assertIn("credential_form", rules_of(signals))

    def test_any_event_handler_counts_as_active_content(self):
        signals, _links, _text = analyze_body("", '<div onmouseover="steal()">hi</div>')
        self.assertIn("script_content", rules_of(signals))

    def test_form_action_is_collected_and_reported(self):
        html = '<form action="https://collect.example/p"><input type="password"></form>'
        signals, links, _text = analyze_body("", html)
        self.assertIn(("https://collect.example/p", "form"), links)
        form = [s for s in signals if s["rule"] == "credential_form"][0]
        self.assertIn("collect.example", form["evidence"])

    def test_srcdoc_iframe_content_is_inspected(self):
        html = '<iframe srcdoc="&lt;form action=&quot;https://x.example/c&quot;&gt;&lt;input type=password&gt;&lt;/form&gt;"></iframe>'
        signals, links, _text = analyze_body("", html)
        self.assertIn("credential_form", rules_of(signals))
        self.assertIn(("https://x.example/c", "form"), links)

    def test_meta_refresh_target_is_collected(self):
        html = '<meta http-equiv="refresh" content="0; url=https://next.example/">'
        signals, links, _text = analyze_body("", html)
        self.assertIn(("https://next.example/", "meta_refresh"), links)
        self.assertIn("script_content", rules_of(signals))


class HiddenContentTests(unittest.TestCase):
    def test_short_preheader_is_not_flagged(self):
        html = '<div style="display:none;max-height:0;overflow:hidden">Your weekly summary</div><p>Hello</p>'
        signals, _links, _text = analyze_body("", html)
        self.assertNotIn("hidden_content", rules_of(signals))

    def test_aria_hidden_spacer_is_not_flagged(self):
        signals, _links, _text = analyze_body("", '<img aria-hidden="true" src="cid:x"><p>Hi</p>')
        self.assertNotIn("hidden_content", rules_of(signals))

    def test_large_hidden_text_block_is_flagged(self):
        html = '<div style="display: none">' + "lorem ipsum " * 40 + "</div><p>Pay now</p>"
        signals, _links, _text = analyze_body("", html)
        self.assertIn("hidden_content", rules_of(signals))

    def test_hidden_link_is_flagged(self):
        signals, _links, _text = analyze_body("", '<span hidden><a href="https://x.example">x</a></span>')
        self.assertIn("hidden_content", rules_of(signals))

    def test_zero_width_inside_words_is_flagged(self):
        signals, _links, _text = analyze_body("Your Pay" + ZWSP + "Pal account", "")
        self.assertIn("hidden_content", rules_of(signals))

    def test_bidi_override_in_text_is_flagged(self):
        signals, _links, _text = analyze_body("Open invoice" + RLO + "fdp.exe", "")
        self.assertIn("hidden_content", rules_of(signals))

    def test_hidden_text_does_not_trigger_lure_language(self):
        html = '<div style="display:none">urgent wire transfer gift card</div><p>Lunch on Friday?</p>'
        signals, _links, _text = analyze_body("", html)
        self.assertNotIn("payment_lure", rules_of(signals))
        self.assertNotIn("urgency_language", rules_of(signals))


class LinkTextTests(unittest.TestCase):
    def test_displayed_domain_differs_from_target(self):
        html = '<a href="https://evil.example/login">https://www.paypal.com/signin</a>'
        signals, _links, _text = analyze_body("", html)
        self.assertIn("link_text_mismatch", rules_of(signals))

    def test_same_organization_is_not_a_mismatch(self):
        html = '<a href="https://click.news.example.com/r/1">www.example.com</a><a href="https://x.example">Click here</a>'
        signals, _links, _text = analyze_body("", html)
        self.assertNotIn("link_text_mismatch", rules_of(signals))

    def test_subject_is_checked_for_lure_language(self):
        signals, _links, _text = analyze_body("hello", "", subject="Final notice: account suspended")
        self.assertIn("urgency_language", rules_of(signals))


if __name__ == "__main__":
    unittest.main()
