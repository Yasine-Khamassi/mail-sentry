from __future__ import annotations

import re
from email.message import Message
from email.utils import getaddresses

AUTH_LINE = re.compile(r"(?i)(?:spf|dkim|dmarc)\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def address_domain(address: str) -> str:
    for _display_name, mailbox in getaddresses([address]):
        if "@" not in mailbox:
            continue
        domain = mailbox.rsplit("@", 1)[1].strip().rstrip(".").lower()
        if domain and re.fullmatch(r"[a-z0-9.-]+", domain):
            return domain
    return ""


def analyze_headers(message: Message, rules: dict) -> tuple[dict, list[dict]]:
    signals = []
    from_values = message.get_all("From", [])
    return_values = message.get_all("Return-Path", [])
    reply_values = message.get_all("Reply-To", [])
    from_domain = address_domain(str(from_values[0])) if from_values else ""
    return_domain = address_domain(str(return_values[0])) if return_values else ""
    reply_domain = address_domain(str(reply_values[0])) if reply_values else ""
    if from_domain and return_domain and from_domain != return_domain:
        signals.append({"rule": "sender_mismatch", "detail": "From and Return-Path use different domains", "evidence": f"{from_domain} vs {return_domain}"})
    if from_domain and reply_domain and from_domain != reply_domain:
        signals.append({"rule": "reply_to_mismatch", "detail": "Reply-To domain differs from From", "evidence": f"{from_domain} vs {reply_domain}"})

    trusted = {x.lower().rstrip(".") for x in rules.get("trusted_authserv_ids", [])}
    auth = []
    for value in message.get_all("Authentication-Results", []):
        # RFC 8601 puts authserv-id before the first semicolon. Do not score untrusted claims.
        prefix = str(value).split(";", 1)[0].strip().split() if ";" in str(value) else []
        authserv = prefix[0].lower().rstrip(".") if prefix else ""
        if not authserv or authserv not in trusted:
            continue
        for match in AUTH_LINE.finditer(str(value).split(";", 1)[1]):
            mechanism = match.group(0).split("=", 1)[0].strip().lower()
            auth.append({"authserv_id": authserv, "mechanism": mechanism, "result": match.group(1).lower(), "trusted": True})
    if any(item["result"] in {"fail", "softfail", "permerror"} for item in auth):
        outcomes = "; ".join(f"{x['authserv_id']} {x['mechanism']}={x['result']}" for x in auth)
        signals.append({"rule": "auth_fail", "detail": "A configured trusted authentication server reported a failed check", "evidence": outcomes})

    received = [str(v) for v in message.get_all("Received", [])]
    ips = {match.group(0) for value in received for match in IP_RE.finditer(value)}
    if len(received) >= 12 or (len(received) >= 4 and len(ips) >= 5):
        signals.append({"rule": "received_anomaly", "detail": "Received chain has an unusual hop count or many distinct IP literals", "evidence": f"{len(received)} Received headers; {len(ips)} IP literals"})
    mailer = " ".join(str(v) for v in message.get_all("X-Mailer", []))
    if mailer and re.search(r"(?i)(?:powershell|python|curl|wget|mass.?mail|bulk|unknown)", mailer):
        signals.append({"rule": "mailer_anomaly", "detail": "X-Mailer value is unusual for a user message", "evidence": mailer})
    header_names = ("From", "To", "Subject", "Date", "Message-ID", "Return-Path", "Reply-To", "Authentication-Results", "Received-SPF", "DKIM-Signature", "X-Mailer")
    raw_headers = {k.lower(): [str(v) for v in message.get_all(k, [])] for k in header_names if message.get_all(k)}
    details = {"subject": str(message.get("Subject", "")), "from": from_values, "to": message.get_all("To", []), "date": str(message.get("Date", "")), "message_id": str(message.get("Message-ID", "")), "headers": raw_headers, "authentication": auth}
    return details, signals
