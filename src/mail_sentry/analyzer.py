from __future__ import annotations

from collections import Counter
from pathlib import Path

from .attachment_analysis import analyze_attachment
from .auth_verification import verify_authentication
from .body_analysis import analyze_body
from .config import load_rules, validate_rules
from .header_analysis import analyze_headers
from .parsing import decode_text, iter_parts, read_message
from .resolver import OfflineResolver
from .scoring import score_signals
from .url_analysis import analyze_urls

SCHEMA_VERSION = "2.1"


def analyze(path: Path, rules: dict | None = None, *, resolver=None, check_spf: bool = False) -> dict:
    """Analyze one message file.

    ``resolver`` answers DNS questions for DKIM keys, SPF, and DMARC. The
    default answers nothing, so the analysis stays offline. ``check_spf``
    turns on SPF evaluation, which needs a resolver with records.
    """
    rules = validate_rules(rules if rules is not None else load_rules())
    limits = rules["limits"]
    resolver = resolver or OfflineResolver()
    message, raw = read_message(path, limits)
    header_data, signals = analyze_headers(message, rules)
    auth, auth_signals = verify_authentication(message, raw, rules, resolver, check_spf)
    signals.extend(auth_signals)
    attachments = []
    plain_parts: list[str] = []
    html_parts: list[str] = []
    defects: Counter[str] = Counter()
    embedded_messages = 0
    text_budget = int(limits["max_text_chars"])
    text_truncated = False

    for part in iter_parts(message, limits["max_mime_parts"]):
        for defect in getattr(part, "defects", []):
            defects[type(defect).__name__] += 1
        content_type = part.get_content_type()
        if content_type == "message/rfc822":
            embedded_messages += 1
        if part.is_multipart():
            continue
        try:
            filename = part.get_filename()
        except (ValueError, LookupError, TypeError):
            filename = "undecodable-filename"
        disposition = part.get_content_disposition()
        maintype = part.get_content_maintype()
        is_body_text = content_type in {"text/plain", "text/html"} and not filename and disposition != "attachment"
        if not is_body_text and (filename or disposition == "attachment" or maintype not in {"text", "message", "multipart"}):
            payload = part.get_payload(decode=True) or b""
            report, found = analyze_attachment(filename or "unnamed-attachment", content_type, payload, rules)
            attachments.append(report)
            signals.extend(found)
            continue
        if not is_body_text:
            continue
        text = decode_text(part)
        if len(text) > text_budget:
            text = text[:text_budget]
            text_truncated = True
        text_budget -= len(text)
        (html_parts if content_type == "text/html" else plain_parts).append(text)

    body_signals, links, body_text = analyze_body("\n".join(plain_parts), "\n".join(html_parts), header_data["subject"])
    signals.extend(body_signals)
    urls, url_signals = analyze_urls(links, body_text, rules)
    signals.extend(url_signals)
    score, verdict, weighted = score_signals(signals, rules)

    if getattr(resolver, "live", False):
        network_note = "Live DNS was queried for DKIM keys, SPF, and DMARC records only. No URL or reputation service was contacted."
    else:
        network_note = "Analysis is static and offline. No URL, DNS name, or reputation service was contacted."
    notes = [
        network_note,
        "auth holds local DKIM, SPF, and DMARC results. They never come from Authentication-Results headers.",
        "wrapped_targets lists URLs decoded from wrapper link parameters. They show what a link names, not where an HTTP request would end up.",
        "Authentication results are used only from trusted_authserv_ids inside the trusted receiving boundary; see ignored_authentication_results for the rest.",
        "Domain age comes only from local domain_hints entries. It is not a registration lookup.",
        "Archive scanning is bounded by entry count, expanded size, nesting depth, and compression ratio limits.",
    ]
    if text_truncated:
        notes.append(f"Body text beyond {limits['max_text_chars']} characters was not analyzed.")
    if embedded_messages:
        notes.append(f"{embedded_messages} attached message(s) found. Their bodies and attachments were analyzed, but their headers were not.")
    return {
        "schema_version": SCHEMA_VERSION,
        "source_file": path.name,
        "message": header_data,
        "auth": auth,
        "verdict": verdict,
        "score": score,
        "signals": weighted,
        "urls": urls,
        "attachments": attachments,
        "parse_defects": dict(defects),
        "summary": {"url_count": len(urls), "attachment_count": len(attachments), "signal_count": len(weighted), "explanation": [s["detail"] for s in weighted if s["weight"]]},
        "analysis_notes": notes,
    }
