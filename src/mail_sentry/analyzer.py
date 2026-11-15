from __future__ import annotations

import html
from pathlib import Path

from .attachment_analysis import analyze_attachment
from .body_analysis import analyze_body
from .config import load_rules, validate_rules
from .header_analysis import analyze_headers
from .parsing import decode_text, iter_parts, parse_message
from .scoring import score_signals
from .url_analysis import analyze_urls


def analyze(path: Path, rules: dict | None = None) -> dict:
    rules = validate_rules(rules if rules is not None else load_rules())
    message = parse_message(path, rules["limits"])
    header_data, signals = analyze_headers(message, rules)
    attachments = []
    plain_parts: list[str] = []
    html_parts: list[str] = []
    for part in iter_parts(message, rules["limits"]["max_mime_parts"]):
        if part.is_multipart():
            continue
        filename = part.get_filename()
        payload = part.get_payload(decode=True) or b""
        if filename or part.get_content_disposition() == "attachment":
            name = filename or "unnamed-attachment"
            report, found_signals = analyze_attachment(name, part.get_content_type(), payload, rules)
            attachments.append(report)
            signals.extend(found_signals)
            continue
        if part.get_content_type() == "text/html":
            html_parts.append(decode_text(part))
        elif part.get_content_type() == "text/plain":
            plain_parts.append(decode_text(part))

    body_signals, body_links, body_text = analyze_body("\n".join(plain_parts), "\n".join(html_parts))
    signals.extend(body_signals)
    links = [(html.unescape(url).strip(), context) for url, context in body_links]
    urls, url_signals = analyze_urls(links, body_text, rules)
    signals.extend(url_signals)
    score, verdict, weighted_signals = score_signals(signals, rules)
    return {
        "schema_version": "1.1",
        "source_file": path.name,
        "message": header_data,
        "verdict": verdict,
        "score": score,
        "signals": weighted_signals,
        "urls": urls,
        "attachments": attachments,
        "summary": {"url_count": len(urls), "attachment_count": len(attachments), "signal_count": len(weighted_signals), "explanation": [s["detail"] for s in weighted_signals]},
        "analysis_notes": [
            "URL analysis is static. Redirect wrappers are decoded for inspection, but destinations are never contacted.",
            "Authentication results are scored only when their authserv-id is listed in trusted_authserv_ids; all header claims can still be forged upstream.",
            "Domain age is used only when supplied as a local domain_hints entry. DNS, registration, and reputation services are not queried.",
            "Archive member scanning is bounded by configured entry count and expanded size limits.",
        ],
    }
