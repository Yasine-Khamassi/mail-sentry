from __future__ import annotations

import re
from html.parser import HTMLParser

from .lure_language import scan_lures
from .url_analysis import BIDI_CONTROLS, clean_url, normalize_url, registrable_hint

# Invisible characters wedged between letters split keywords so filters miss
# them ("Pa<U+200B>yPal"). A lone character elsewhere is common in templates.
IN_WORD_INVISIBLE = re.compile(r"(?<=\w)[\u200b\u2060-\u2064\ufeff]+(?=\w)")
HIDDEN_STYLE = re.compile(r"(?i)(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?![.\d])(?:px|pt|em|rem|%)?|opacity\s*:\s*0(?![.\d])|max-height\s*:\s*0(?![.\d])(?:px)?\s*;[^\"']*overflow\s*:\s*hidden)")
LINK_TEXT_DOMAIN = re.compile(r"(?i)^\s*(?:https?://)?((?:[a-z0-9\-]+\.)+[a-z]{2,})(?:[/:?#]\S*)?\s*$")
VOID_TAGS = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}
URL_ATTRS = {"a": "href", "area": "href", "form": "action", "iframe": "src", "frame": "src", "embed": "src", "object": "data"}
MAX_STACK = 512
HIDDEN_TEXT_THRESHOLD = 200


class HtmlInspector(HTMLParser):
    """Collect links, forms, active content, and visible versus hidden text."""

    def __init__(self, depth: int = 0) -> None:
        super().__init__(convert_charrefs=True)
        self.depth = depth
        self.links: list[tuple[str, str]] = []
        self.anchor_pairs: list[tuple[str, str]] = []
        self.forms = 0
        self.form_actions: list[str] = []
        self.password_inputs = 0
        self.active: list[str] = []
        self.hidden_links = 0
        self.visible_text: list[str] = []
        self.hidden_text: list[str] = []
        self.srcdoc: list[str] = []
        self._stack: list[tuple[str, bool]] = []
        self._anchor: list[str] | None = None
        self._anchor_href = ""
        self._skip = 0

    @property
    def hidden(self) -> bool:
        return any(flag for _tag, flag in self._stack)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        attr = {k.lower(): (v or "") for k, v in attrs}
        is_hidden = "hidden" in attr or bool(HIDDEN_STYLE.search(attr.get("style", ""))) or (tag == "input" and attr.get("type", "").strip().lower() == "hidden")
        if tag in {"script", "style", "title"}:
            self._skip += 1
        if tag == "script":
            self.active.append("script element")
        handlers = sorted(k for k in attr if k.startswith("on") and len(k) > 2)
        if handlers:
            self.active.append("event handler attribute " + handlers[0])
        for name in ("href", "src", "action", "formaction", "data", "xlink:href"):
            value = clean_url(attr.get(name, "")).lower()
            if value.startswith(("javascript:", "vbscript:")):
                self.active.append(f"{value.split(':', 1)[0]} URL in {tag} {name}")
        url_attr = URL_ATTRS.get(tag)
        if url_attr and attr.get(url_attr, "").strip():
            context = {"a": "anchor", "area": "anchor", "form": "form"}.get(tag, "embedded_frame")
            self.links.append((attr[url_attr].strip(), context))
            if self.hidden or is_hidden:
                self.hidden_links += 1
        if tag == "button" and attr.get("formaction", "").strip():
            self.links.append((attr["formaction"].strip(), "form"))
        if tag == "form":
            self.forms += 1
            if attr.get("action", "").strip():
                self.form_actions.append(attr["action"].strip())
        if tag == "input" and attr.get("type", "").strip().lower() == "password":
            self.password_inputs += 1
        if tag in {"iframe", "frame", "object", "embed"}:
            self.active.append(f"{tag} element")
        if tag == "iframe" and attr.get("srcdoc"):
            self.srcdoc.append(attr["srcdoc"])
        if tag == "meta" and attr.get("http-equiv", "").strip().lower() == "refresh":
            target = re.search(r"(?i)url\s*=\s*['\"]?([^'\";]+)", attr.get("content", ""))
            if target:
                self.links.append((target.group(1).strip(), "meta_refresh"))
                self.active.append("meta refresh redirect")
        if tag == "a":
            self._anchor = []
            self._anchor_href = attr.get("href", "").strip()
        if tag not in VOID_TAGS and len(self._stack) < MAX_STACK:
            self._stack.append((tag, is_hidden))

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        if tag.lower() not in VOID_TAGS:
            self.handle_endtag(tag)

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag in {"script", "style", "title"} and self._skip:
            self._skip -= 1
        if tag == "a" and self._anchor is not None:
            self.anchor_pairs.append((self._anchor_href, " ".join("".join(self._anchor).split())))
            self._anchor = None
        for index in range(len(self._stack) - 1, -1, -1):
            if self._stack[index][0] == tag:
                del self._stack[index:]
                break

    def handle_data(self, data: str) -> None:
        if self._skip:
            return
        if self._anchor is not None:
            self._anchor.append(data)
        (self.hidden_text if self.hidden else self.visible_text).append(data)


def inspect_html(html_text: str, max_frame_depth: int = 2) -> HtmlInspector:
    """Parse HTML, including iframe srcdoc documents up to a fixed depth."""
    root = HtmlInspector()
    pending = [(html_text, 0)]
    while pending:
        content, depth = pending.pop()
        parser = root if depth == 0 else HtmlInspector(depth)
        try:
            parser.feed(content)
            parser.close()
        except (AssertionError, ValueError):
            pass
        if parser is not root:
            root.links.extend(parser.links)
            root.anchor_pairs.extend(parser.anchor_pairs)
            root.forms += parser.forms
            root.form_actions.extend(parser.form_actions)
            root.password_inputs += parser.password_inputs
            root.active.extend(parser.active)
            root.hidden_links += parser.hidden_links
            root.visible_text.extend(parser.visible_text)
            root.hidden_text.extend(parser.hidden_text)
        if depth < max_frame_depth:
            pending.extend((doc, depth + 1) for doc in parser.srcdoc)
        if depth and parser.srcdoc:
            root.active.append("nested iframe srcdoc")
    return root


def _link_text_mismatches(pairs: list[tuple[str, str]]) -> list[str]:
    """Anchors whose visible text names one domain while the link goes elsewhere."""
    found = []
    for href, text in pairs:
        match = LINK_TEXT_DOMAIN.match(text)
        if not match or not href:
            continue
        shown = normalize_url(match.group(1))
        target = normalize_url(href)
        if not shown or not target:
            continue
        if registrable_hint(shown["host"]) != registrable_hint(target["host"]):
            found.append(f"text '{text[:80]}' links to {target['host']}")
    return found


def analyze_body(plain: str, html_text: str, subject: str = "", content_language: str = "", details: dict | None = None) -> tuple[list[dict], list[tuple[str, str]], str]:
    """Return (signals, html links with context, text for URL extraction).

    When ``details`` is a dict, the language report is stored in
    ``details["language"]``.
    """
    inspector = inspect_html(html_text) if html_text else HtmlInspector()
    visible = " ".join(inspector.visible_text)
    hidden = " ".join(inspector.hidden_text)
    signals: list[dict] = []

    lure_signals, language = scan_lures(f"{subject}\n{plain}\n{visible}", content_language)
    signals.extend(lure_signals)
    if details is not None:
        details["language"] = language

    if inspector.password_inputs:
        if inspector.forms:
            targets = ", ".join(inspector.form_actions[:3]) or "no action attribute"
            signals.append({"rule": "credential_form", "detail": "HTML message contains a form with a password field", "evidence": f"form action: {targets}"})
        else:
            signals.append({"rule": "credential_form", "detail": "HTML message contains a password field", "evidence": "password input"})

    reasons = []
    hidden_chars = len(hidden.strip())
    if hidden_chars >= HIDDEN_TEXT_THRESHOLD:
        reasons.append(f"{hidden_chars} characters of hidden text")
    if inspector.hidden_links:
        reasons.append(f"{inspector.hidden_links} link(s) inside hidden elements")
    split_words = IN_WORD_INVISIBLE.findall(f"{subject}\n{plain}\n{visible}")
    if split_words:
        reasons.append(f"{len(split_words)} invisible character run(s) inside words")
    if BIDI_CONTROLS.search(f"{subject}\n{plain}\n{visible}"):
        reasons.append("bidirectional override characters in text")
    if reasons:
        signals.append({"rule": "hidden_content", "detail": "Message hides text, links, or characters from the reader", "evidence": "; ".join(reasons)})

    if inspector.active:
        signals.append({"rule": "script_content", "detail": "HTML contains scripts, event handlers, frames, or automatic redirects", "evidence": ", ".join(dict.fromkeys(inspector.active))})

    mismatches = _link_text_mismatches(inspector.anchor_pairs)
    if mismatches:
        signals.append({"rule": "link_text_mismatch", "detail": "Link text shows one domain but the link points to another", "evidence": "; ".join(mismatches[:3])})

    return signals, inspector.links, f"{plain}\n{visible}\n{hidden}"
