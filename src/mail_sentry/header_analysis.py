from __future__ import annotations

import re
from email.message import Message
from email.utils import getaddresses

from .url_analysis import lookalike, registrable_hint

AUTH_RESULT = re.compile(r"(?i)\b(spf|dkim|dmarc|arc)\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror|policy|hardfail)\b")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
RECEIVED_BY = re.compile(r"(?i)\bby\s+([a-z0-9.\-]+)")
EMAIL_IN_TEXT = re.compile(r"(?i)[a-z0-9._%+\-]+@((?:[a-z0-9\-]+\.)+[a-z]{2,})")
DOMAIN_RE = re.compile(r"[a-z0-9.\-]+")


def _safe_str(value: object) -> str:
    try:
        return str(value)
    except Exception:  # malformed header objects from the email package
        return ""


def _strip_comments(value: str) -> str:
    """Remove RFC 5322 comments so text like ``(spf=pass)`` is not read as a result."""
    previous = None
    while previous != value:
        previous = value
        value = re.sub(r"\([^()]*\)", " ", value)
    return value


def parse_mailboxes(values: list[str]) -> list[tuple[str, str]]:
    """Return (display_name, addr_spec) pairs, skipping empty group syntax."""
    pairs = []
    for name, address in getaddresses(values):
        if name or address:
            pairs.append((name.strip(), address.strip()))
    return pairs


def address_domain(address: str) -> str:
    """Domain of the first addr-spec in a header value; display names are ignored."""
    for _name, mailbox in parse_mailboxes([address]):
        if "@" not in mailbox:
            continue
        domain = mailbox.rsplit("@", 1)[1].strip().strip("[]").rstrip(".").lower()
        try:
            domain = domain.encode("idna").decode("ascii") if not domain.isascii() else domain
        except UnicodeError:
            continue
        if domain and DOMAIN_RE.fullmatch(domain):
            return domain
    return ""


def _host_matches(host: str, patterns: set[str]) -> bool:
    host = host.lower().rstrip(".")
    return any(host == p or host.endswith("." + p.lstrip(".")) for p in patterns)


def trusted_authentication(message: Message, rules: dict) -> tuple[list[dict], list[dict]]:
    """Read Authentication-Results only from the trusted receiving boundary.

    A header counts only when (1) its authserv-id is listed in
    ``trusted_authserv_ids`` and (2) it sits inside the block of headers
    written by the trusted receiving gateway. That block runs from the top of
    the message through the contiguous chain of Received headers whose ``by``
    host is in ``trusted_receivers`` (defaults to the authserv IDs), and ends
    at the first Received header added by any other host. Headers below that
    point arrived with the message and are reported as ignored. Only the
    topmost trusted header per authserv-id is used.
    """
    authserv_ids = {x.lower().rstrip(".") for x in rules.get("trusted_authserv_ids", [])}
    receivers = {x.lower().rstrip(".") for x in rules.get("trusted_receivers", [])} or set(authserv_ids)
    accepted: list[dict] = []
    ignored: list[dict] = []
    if not authserv_ids:
        for value in message.get_all("Authentication-Results", []) or []:
            ignored.append({"authserv_id": _authserv(_safe_str(value)), "reason": "no trusted_authserv_ids configured"})
        return accepted, ignored

    items = [(name.lower(), _safe_str(value)) for name, value in message.raw_items()]
    hops = []
    for position, (lowered, text) in enumerate(items):
        if lowered == "received":
            by = RECEIVED_BY.search(_strip_comments(text))
            hops.append((position, bool(by) and _host_matches(by.group(1), receivers)))
    first_trusted = next((i for i, (_pos, trusted) in enumerate(hops) if trusted), None)
    if first_trusted is None:
        boundary = hops[0][0] if hops else len(items)
    else:
        later = [pos for pos, trusted in hops[first_trusted:] if not trusted]
        boundary = later[0] if later else len(items)

    used_ids: set[str] = set()
    for position, (lowered, text) in enumerate(items):
        inside = position < boundary
        if lowered != "authentication-results":
            continue
        authserv = _authserv(text)
        if not authserv:
            ignored.append({"authserv_id": "", "reason": "missing authserv-id"})
        elif authserv not in authserv_ids:
            ignored.append({"authserv_id": authserv, "reason": "authserv-id not trusted"})
        elif not inside:
            ignored.append({"authserv_id": authserv, "reason": "below the trusted receiving boundary"})
        elif authserv in used_ids:
            ignored.append({"authserv_id": authserv, "reason": "a higher header from the same authserv-id was already used"})
        else:
            used_ids.add(authserv)
            body = _strip_comments(text.split(";", 1)[1])
            for match in AUTH_RESULT.finditer(body):
                accepted.append({"authserv_id": authserv, "mechanism": match.group(1).lower(), "result": match.group(2).lower(), "trusted": True})
    if first_trusted is None and accepted:
        # No Received header proves where the gateway boundary is. Keep the
        # result but say so, so analysts know the provenance is weaker.
        for item in accepted:
            item["boundary"] = "no Received header from a trusted receiver was found"
    return accepted, ignored


def _authserv(value: str) -> str:
    if ";" not in value:
        return ""
    prefix = _strip_comments(value.split(";", 1)[0]).split()
    return prefix[0].lower().rstrip(".") if prefix else ""


def analyze_headers(message: Message, rules: dict) -> tuple[dict, list[dict]]:
    signals: list[dict] = []
    trusted_domains = rules.get("trusted_domains", [])
    from_values = [_safe_str(v) for v in message.get_all("From", []) or []]
    return_values = [_safe_str(v) for v in message.get_all("Return-Path", []) or []]
    reply_values = [_safe_str(v) for v in message.get_all("Reply-To", []) or []]
    from_mailboxes = parse_mailboxes(from_values)
    from_domain = address_domain(from_values[0]) if from_values else ""
    return_domain = address_domain(return_values[0]) if return_values else ""
    reply_domain = address_domain(reply_values[0]) if reply_values else ""
    from_org = registrable_hint(from_domain) if from_domain else ""

    problems = []
    if len(from_values) > 1:
        problems.append(f"{len(from_values)} From headers")
    if len(from_mailboxes) > 1:
        problems.append(f"{len(from_mailboxes)} mailboxes in From")
    if from_values and not from_domain:
        problems.append("From has no parseable address")
    if problems:
        signals.append({"rule": "malformed_sender", "detail": "From header is missing, duplicated, or cannot be parsed into one address", "evidence": "; ".join(problems)})

    if from_domain and return_domain and from_org != registrable_hint(return_domain):
        signals.append({"rule": "sender_mismatch", "detail": "From and Return-Path belong to different organizational domains", "evidence": f"{from_domain} vs {return_domain}"})
    if from_domain and reply_domain and from_org != registrable_hint(reply_domain):
        signals.append({"rule": "reply_to_mismatch", "detail": "Reply-To organizational domain differs from From", "evidence": f"{from_domain} vs {reply_domain}"})

    if from_domain:
        brand = lookalike(from_domain, trusted_domains)
        if brand:
            signals.append({"rule": "sender_lookalike", "detail": f"Sender domain resembles a trusted brand domain ({brand})", "evidence": from_domain})
        display = from_mailboxes[0][0] if from_mailboxes else ""
        spoof = _display_name_spoof(display, from_domain, trusted_domains)
        if spoof:
            signals.append({"rule": "display_name_spoof", "detail": "Sender display name claims an address or brand that the real address does not belong to", "evidence": spoof})

    auth, ignored = trusted_authentication(message, rules)
    failed = [x for x in auth if x["result"] in {"fail", "softfail", "permerror", "hardfail"} and x["mechanism"] in {"spf", "dkim", "dmarc"}]
    if failed:
        outcomes = "; ".join(f"{x['authserv_id']} {x['mechanism']}={x['result']}" for x in failed)
        signals.append({"rule": "auth_fail", "detail": "The trusted receiving gateway reported a failed authentication check", "evidence": outcomes})

    received = [_safe_str(v) for v in message.get_all("Received", []) or []]
    ips = {match.group(0) for value in received for match in IP_RE.finditer(value)}
    if len(received) >= 12 or (len(received) >= 4 and len(ips) >= 5):
        signals.append({"rule": "received_anomaly", "detail": "Received chain has an unusual hop count or many distinct IP literals", "evidence": f"{len(received)} Received headers; {len(ips)} IP literals"})
    mailer = " ".join(_safe_str(v) for v in message.get_all("X-Mailer", []) or [])
    if mailer and re.search(r"(?i)(?:powershell|curl|wget|mass.?mail|bulk.?mail|unknown)", mailer):
        signals.append({"rule": "mailer_anomaly", "detail": "X-Mailer value is unusual for a user message", "evidence": mailer[:200]})

    header_names = ("From", "To", "Subject", "Date", "Message-ID", "Return-Path", "Reply-To", "Authentication-Results", "Received-SPF", "DKIM-Signature", "X-Mailer")
    raw_headers = {k.lower(): [_safe_str(v) for v in message.get_all(k, [])] for k in header_names if message.get_all(k)}
    details = {
        "subject": _safe_str(message.get("Subject", "")),
        "from": from_values,
        "from_address": from_mailboxes[0][1] if from_mailboxes else "",
        "from_display_name": from_mailboxes[0][0] if from_mailboxes else "",
        "to": [_safe_str(v) for v in message.get_all("To", []) or []],
        "date": _safe_str(message.get("Date", "")),
        "message_id": _safe_str(message.get("Message-ID", "")),
        "headers": raw_headers,
        "authentication": auth,
        "ignored_authentication_results": ignored,
    }
    return details, signals


def _display_name_spoof(display: str, from_domain: str, trusted_domains: list[str]) -> str:
    if not display:
        return ""
    from_org = registrable_hint(from_domain)
    embedded = EMAIL_IN_TEXT.search(display)
    if embedded and registrable_hint(embedded.group(1).lower()) != from_org:
        return f"display name shows {embedded.group(0)} but address is at {from_domain}"
    words = {w.lower() for w in re.findall(r"[A-Za-z0-9]+", display)}
    for trusted in trusted_domains:
        stem = registrable_hint(trusted.lower()).split(".")[0]
        if len(stem) >= 3 and stem in words and not (from_domain == registrable_hint(trusted) or from_domain.endswith("." + registrable_hint(trusted))):
            return f"display name mentions {stem} but address is at {from_domain}"
    return ""
