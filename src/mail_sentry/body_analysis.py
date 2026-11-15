from __future__ import annotations

import re
from html.parser import HTMLParser


SUSPICIOUS_LANG = {
    "urgency_language": re.compile(r"(?i)\b(?:immediately|urgent|within\s+\d+\s+hours?|act now|final notice|account.{0,20}(?:suspend|locked|close)|verify.{0,20}(?:account|identity)|unusual sign.?in)\b"),
    "payment_lure": re.compile(r"(?i)\b(?:invoice overdue|payment failed|wire transfer|bank details|gift card|pay now|refund pending|delivery fee|customs fee|package held)\b"),
}
ZERO_WIDTH = re.compile("[\u200b-\u200f\u202a-\u202e\ufeff]")
HIDDEN_STYLE = re.compile(r"(?is)(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?:px|pt|em)?|opacity\s*:\s*0)")
JS_PATTERN = re.compile(r"(?is)<script\b|\bon(?:error|load|click)\s*=|javascript\s*:")
FORM_PASSWORD = re.compile(r"(?is)<input\b[^>]*type\s*=\s*['\"]?password")


class LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[tuple[str, str]] = []
        self.forms = 0
        self.hidden = False
        self.scripts = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr = {k.lower(): v or "" for k, v in attrs}
        if tag.lower() == "a" and attr.get("href"):
            self.links.append((attr["href"], "anchor"))
        if tag.lower() == "form":
            self.forms += 1
            if attr.get("action"):
                self.links.append((attr["action"], "form"))
        if tag.lower() == "script":
            self.scripts = True
        if HIDDEN_STYLE.search(attr.get("style", "")) or "hidden" in attr or attr.get("aria-hidden") == "true":
            self.hidden = True

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)


def analyze_body(plain: str, html_text: str) -> tuple[list[dict], list[tuple[str, str]], str]:
    import html

    decoded_html = html.unescape(html_text)
    parser = LinkParser()
    try:
        parser.feed(decoded_html)
    except Exception:
        pass
    combined = plain + "\n" + decoded_html
    visible = re.sub(r"(?is)<(script|style)\b.*?</\1>", " ", decoded_html)
    visible = re.sub(r"<[^>]+>", " ", visible)
    signals: list[dict] = []
    text = plain + " " + visible
    for key, pattern in SUSPICIOUS_LANG.items():
        match = pattern.search(text)
        if match:
            signals.append({"rule": key, "detail": "Message uses language commonly seen in credential or payment lures", "evidence": match.group(0)})
    if FORM_PASSWORD.search(decoded_html):
        detail = "HTML message contains a form and password input" if parser.forms else "HTML message contains a password input"
        signals.append({"rule": "credential_form", "detail": detail, "evidence": "password input inside form-capable HTML" if parser.forms else "password input"})
    if parser.hidden or HIDDEN_STYLE.search(decoded_html) or ZERO_WIDTH.search(combined):
        signals.append({"rule": "hidden_content", "detail": "Message contains hidden or zero-width content", "evidence": "hidden style, hidden attribute, or zero-width Unicode"})
    if parser.scripts or JS_PATTERN.search(decoded_html):
        signals.append({"rule": "script_content", "detail": "HTML contains script or active event-handler content", "evidence": "script tag, event handler, or javascript URL"})
    return signals, parser.links, combined
