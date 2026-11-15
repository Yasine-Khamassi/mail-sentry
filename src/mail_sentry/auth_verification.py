"""Local DKIM, SPF, and DMARC evaluation.

These checks never read Authentication-Results headers. DKIM signatures are
verified against the raw message bytes, SPF is evaluated for the client IP
recorded by your own receiving gateway, and DMARC alignment is computed from
those two local results only.

Results use the RFC 8601 vocabulary: ``pass``, ``fail``, ``softfail`` (SPF
only), ``neutral``, ``none``, ``temperror``, and ``permerror``. ``neutral``
for DKIM means a signature exists but could not be processed here, for
example because DNS is disabled and no local key record was supplied.
"""
from __future__ import annotations

import ipaddress
import re
import threading
from email.message import Message

from .header_analysis import RECEIVED_BY, _host_matches, _safe_str, _strip_comments, address_domain, parse_mailboxes
from .resolver import DnsDisabled, DnsTempError, OfflineResolver
from .url_analysis import registrable_hint

MAX_SIGNATURES = 5
RECEIVED_FROM = re.compile(r"(?is)^\s*from\s+(\S+)(.*?)(?:\bby\s|;|$)")
BRACKET_IP = re.compile(r"(?i)\[(?:ipv6:)?([0-9a-f:.]+)\]")
BARE_IP = re.compile(r"(?i)(?<![\w.:])((?:\d{1,3}\.){3}\d{1,3}|[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7})(?![\w.:])")
HELO_COMMENT = re.compile(r"(?i)\bhelo[=\s]+([a-z0-9.\-\[\]:]+)")
RESULT_RANK = {"pass": 6, "fail": 5, "permerror": 4, "temperror": 3, "neutral": 2, "none": 1}
_SPF_LOCK = threading.Lock()


def _tags(value: str) -> dict[str, str]:
    tags = {}
    for item in re.sub(r"\s+", "", value).split(";"):
        if "=" in item:
            key, _, val = item.partition("=")
            tags.setdefault(key.lower(), val)
    return tags


def _aligned(domain: str | None, from_domain: str, mode: str) -> bool:
    if not domain or not from_domain:
        return False
    domain = domain.lower().rstrip(".")
    if mode == "s":
        return domain == from_domain
    return registrable_hint(domain) == registrable_hint(from_domain)


# --------------------------------------------------------------------- DKIM

def verify_dkim(raw: bytes | None, message: Message, resolver) -> dict:
    headers = [_safe_str(v) for v in message.get_all("DKIM-Signature", []) or []]
    report: dict = {"result": "none", "verified": False, "d_tag": None, "s_tag": None, "errors": [], "signatures": []}
    if not headers:
        return report
    if raw is None:
        return _dkim_unprocessed(report, headers, "raw message bytes are not available for this input type, so signatures were not verified")
    try:
        import dkim  # type: ignore
    except ImportError:
        return _dkim_unprocessed(report, headers, "DKIM verification needs dkimpy: pip install mail-sentry[auth]")

    for index, header in enumerate(headers[:MAX_SIGNATURES]):
        tags = _tags(header)
        entry = {"d_tag": tags.get("d", "").lower() or None, "s_tag": tags.get("s") or None, "result": "permerror", "error": ""}
        state: dict = {}

        def dnsfunc(name, timeout=5, _state=state):
            host = name.decode("ascii", "replace") if isinstance(name, bytes) else str(name)
            try:
                records = resolver.query(host, "TXT")
            except DnsDisabled as exc:
                _state["disabled"] = str(exc)
                return None
            except DnsTempError as exc:
                _state["temp"] = str(exc)
                return None
            if not records:
                _state["missing"] = f"no DKIM key record at {host.rstrip('.')}"
                return None
            record = next((r for r in records if "p=" in r), records[0]).encode("utf-8", "replace")
            try:
                dkim.evaluate_pk(name, record)
            except Exception as exc:  # dkimpy raises several types for bad keys
                _state["bad_key"] = f"unusable DKIM key record: {exc}"
            return record

        verified = False
        failure = ""
        try:
            verifier = dkim.DKIM(raw, minkey=1024, timeout=5)
            verified = bool(verifier.verify(idx=index, dnsfunc=dnsfunc))
        except dkim.ValidationError as exc:
            failure = str(exc)
            if "body hash mismatch" not in failure:
                state.setdefault("malformed", failure)
        except dkim.DKIMException as exc:
            failure = str(exc)
            state.setdefault("malformed", failure)
        except Exception as exc:  # hostile input can reach unexpected corners of dkimpy
            state.setdefault("malformed", f"{type(exc).__name__}: {exc}")

        if state.get("disabled"):
            entry.update(result="neutral", error="public key not looked up: DNS is disabled (use --dns or --dns-records)")
        elif state.get("temp"):
            entry.update(result="temperror", error=f"public key lookup failed: {state['temp']}")
        elif state.get("missing"):
            entry.update(result="permerror", error=state["missing"])
        elif state.get("bad_key"):
            entry.update(result="permerror", error=state["bad_key"])
        elif verified:
            entry.update(result="pass")
        elif "body hash mismatch" in failure:
            entry.update(result="fail", error="body hash mismatch: the body changed after signing")
        elif state.get("malformed"):
            entry.update(result="permerror", error=f"signature could not be processed: {state['malformed']}"[:300])
        else:
            entry.update(result="fail", error=(failure or "signature does not match the signed headers")[:300])
        report["signatures"].append(entry)
        if entry["error"]:
            report["errors"].append(f"d={entry['d_tag']} s={entry['s_tag']}: {entry['error']}")
    if len(headers) > MAX_SIGNATURES:
        report["errors"].append(f"only the first {MAX_SIGNATURES} of {len(headers)} signatures were checked")
    _summarize_dkim(report)
    return report


def _dkim_unprocessed(report: dict, headers: list[str], reason: str) -> dict:
    for header in headers[:MAX_SIGNATURES]:
        tags = _tags(header)
        report["signatures"].append({"d_tag": tags.get("d", "").lower() or None, "s_tag": tags.get("s") or None, "result": "neutral", "error": reason})
    report["errors"].append(reason)
    _summarize_dkim(report)
    return report


def _summarize_dkim(report: dict) -> None:
    best = max(report["signatures"], key=lambda s: RESULT_RANK.get(s["result"], 0))
    report.update(result=best["result"], d_tag=best["d_tag"], s_tag=best["s_tag"], verified=best["result"] == "pass")


# ---------------------------------------------------------------------- SPF

def connecting_client(message: Message, rules: dict) -> tuple[dict | None, str]:
    """Find the client that handed the message to your gateway.

    Uses the same boundary as Authentication-Results trust: walk the
    Received chain from the first hop written by a trusted receiver down
    through the contiguous trusted hops. The ``from`` clause of the last
    trusted hop names the first untrusted host. Without trusted receivers,
    the topmost Received header is used and the report says so.
    """
    authserv_ids = {x.lower().rstrip(".") for x in rules.get("trusted_authserv_ids", [])}
    receivers = {x.lower().rstrip(".") for x in rules.get("trusted_receivers", [])} or authserv_ids
    received = [_safe_str(v) for v in message.get_all("Received", []) or []]
    if not received:
        return None, "no Received header names a connecting client"
    note = ""
    chosen = None
    if receivers:
        trusted = []
        for value in received:
            by = RECEIVED_BY.search(_strip_comments(value))
            trusted.append(bool(by) and _host_matches(by.group(1), receivers))
        if True in trusted:
            index = trusted.index(True)
            while index + 1 < len(trusted) and trusted[index + 1]:
                index += 1
            chosen = received[index]
        else:
            note = "no Received header from a trusted receiver; used the topmost Received header"
    else:
        note = "no trusted_receivers configured; used the topmost Received header"
    if chosen is None:
        chosen = received[0]
    hop = _parse_received_from(chosen)
    if hop is None:
        return None, (note + "; " if note else "") + "the boundary Received header has no client IP"
    return hop, note


def _parse_received_from(value: str) -> dict | None:
    match = RECEIVED_FROM.search(value)
    if not match:
        return None
    clause = match.group(1) + " " + match.group(2)
    candidates = [m.group(1) for m in BRACKET_IP.finditer(clause)] + [m.group(1) for m in BARE_IP.finditer(clause)]
    ip = None
    for candidate in candidates:
        try:
            ip = str(ipaddress.ip_address(candidate))
            break
        except ValueError:
            continue
    if ip is None:
        return None
    helo_match = HELO_COMMENT.search(match.group(2))
    helo = (helo_match.group(1) if helo_match else match.group(1)).strip("[]()").rstrip(".").lower()
    return {"ip": ip, "helo": helo}


def check_spf(message: Message, rules: dict, resolver, enabled: bool) -> dict:
    return_values = [_safe_str(v) for v in message.get_all("Return-Path", []) or []]
    mail_from = ""
    for _name, address in parse_mailboxes(return_values[:1]):
        mail_from = address
    report: dict = {"result": None, "checked": False, "ip": None, "helo": None, "from": mail_from or None, "domain": None, "errors": []}
    if not enabled:
        report["errors"].append("SPF not checked (enable with --check-spf)")
        return report
    try:
        import spf  # type: ignore
    except ImportError:
        report["errors"].append("SPF checks need pyspf: pip install mail-sentry[auth]")
        return report
    hop, note = connecting_client(message, rules)
    if note:
        report["errors"].append(note)
    if hop is None:
        report.update(result="none", checked=True)
        return report
    report.update(ip=hop["ip"], helo=hop["helo"])
    sender = mail_from if "@" in mail_from else f"postmaster@{hop['helo']}"
    report["domain"] = sender.rsplit("@", 1)[1].lower()

    def lookup(name, qtype, strict=True, timeout=None):
        try:
            values = resolver.query(str(name), qtype)
        except (DnsTempError, DnsDisabled) as exc:
            raise spf.TempError(f"DNS {exc}") from exc
        answers = []
        for value in values:
            if qtype in {"TXT", "SPF"}:
                answers.append(((name, qtype), (value.encode("utf-8", "replace"),)))
            elif qtype == "MX":
                preference, _, host = value.partition(" ")
                answers.append(((name, qtype), (int(preference or 0), host.strip())))
            else:
                answers.append(((name, qtype), value))
        return answers

    with _SPF_LOCK:
        original = spf.DNSLookup
        spf.DNSLookup = lookup
        try:
            result, _code, explanation = spf.query(i=hop["ip"], s=sender, h=hop["helo"] or report["domain"], timeout=5, querytime=20).check()
        except Exception as exc:  # pyspf on hostile records; record it rather than crash
            result, explanation = "permerror", f"{type(exc).__name__}: {exc}"
        finally:
            spf.DNSLookup = original
    report.update(result=str(result).lower(), checked=True)
    if report["result"] in {"temperror", "permerror"} and explanation:
        report["errors"].append(str(explanation)[:300])
    return report


# -------------------------------------------------------------------- DMARC

def _dmarc_record(domain: str, resolver) -> tuple[dict | None, str, str]:
    """Return (tags, looked_up_domain, error). tags is None when no record exists."""
    org = registrable_hint(domain)
    for name in dict.fromkeys((domain, org)):
        values = resolver.query(f"_dmarc.{name}", "TXT")
        records = [v for v in values if v.strip().lower().startswith("v=dmarc1")]
        if len(records) > 1:
            return None, name, "more than one DMARC record"
        if records:
            return _tags(records[0]), name, ""
    return None, "", ""


def evaluate_dmarc(message: Message, dkim_report: dict, spf_report: dict, resolver) -> dict:
    from_values = [_safe_str(v) for v in message.get_all("From", []) or []]
    from_domain = address_domain(from_values[0]) if from_values else ""
    report: dict = {"result": "none", "policy": None, "from_domain": from_domain or None, "alignment": {"dkim": False, "spf": None, "adkim": "r", "aspf": "r"}, "errors": []}
    if len(from_values) != 1 or len(parse_mailboxes(from_values)) != 1 or not from_domain:
        report["result"] = "permerror"
        report["errors"].append("DMARC needs exactly one From address with a domain")
        return report

    tags = None
    record_known_absent = False
    lookup_temp = False
    try:
        tags, found_at, error = _dmarc_record(from_domain, resolver)
        if error:
            report["errors"].append(error)
        if tags is None and not error:
            record_known_absent = True
        if tags is not None:
            policy = tags.get("sp") if found_at != from_domain and tags.get("sp") else tags.get("p")
            report["policy"] = (policy or "none").lower()
            report["alignment"]["adkim"] = "s" if tags.get("adkim", "r").lower() == "s" else "r"
            report["alignment"]["aspf"] = "s" if tags.get("aspf", "r").lower() == "s" else "r"
    except DnsDisabled:
        report["errors"].append("DMARC policy not looked up: DNS is disabled (use --dns or --dns-records)")
    except DnsTempError as exc:
        lookup_temp = True
        report["errors"].append(f"DMARC policy lookup failed: {exc}")

    alignment = report["alignment"]
    alignment["dkim"] = any(s["result"] == "pass" and _aligned(s["d_tag"], from_domain, alignment["adkim"]) for s in dkim_report["signatures"])
    if spf_report.get("checked"):
        alignment["spf"] = spf_report["result"] == "pass" and _aligned(spf_report.get("domain"), from_domain, alignment["aspf"])

    dkim_result = dkim_report["result"]
    spf_result = spf_report.get("result")
    if lookup_temp:
        report["result"] = "temperror"
    elif record_known_absent:
        report["result"] = "none"
        searched = " or ".join(dict.fromkeys((from_domain, registrable_hint(from_domain))))
        report["errors"].append(f"no DMARC record for {searched}")
    elif alignment["dkim"] or alignment["spf"]:
        report["result"] = "pass"
    elif "temperror" in {dkim_result, spf_result}:
        report["result"] = "temperror"
    elif not spf_report.get("checked"):
        report["result"] = "neutral"
        report["errors"].append("no aligned DKIM pass, and SPF was not checked, so DMARC could not be decided")
    elif dkim_result == "neutral":
        report["result"] = "neutral"
        report["errors"].append("no aligned SPF pass, and DKIM signatures could not be processed")
    else:
        report["result"] = "fail"
    return report


# ------------------------------------------------------------------ driver

def verify_authentication(message: Message, raw: bytes | None, rules: dict, resolver=None, check_spf_enabled: bool = False) -> tuple[dict, list[dict]]:
    resolver = resolver or OfflineResolver()
    dkim_report = verify_dkim(raw, message, resolver)
    spf_report = check_spf(message, rules, resolver, check_spf_enabled)
    dmarc_report = evaluate_dmarc(message, dkim_report, spf_report, resolver)
    signals = []
    failed = [s for s in dkim_report["signatures"] if s["result"] == "fail"]
    if failed:
        signals.append({"rule": "dkim_fail", "detail": "A DKIM signature failed cryptographic verification", "evidence": "; ".join(f"d={s['d_tag']} s={s['s_tag']}: {s['error']}" for s in failed)[:300]})
    if spf_report.get("result") in {"fail", "softfail"}:
        signals.append({"rule": "spf_fail", "detail": f"SPF {spf_report['result']} for the connecting client", "evidence": f"{spf_report['ip']} is not permitted to send for {spf_report['domain']}"})
    if dmarc_report["result"] == "fail":
        signals.append({"rule": "dmarc_fail", "detail": "No DKIM or SPF pass aligns with the From domain", "evidence": f"From {dmarc_report['from_domain']}; policy={dmarc_report['policy'] or 'not looked up'}"})
    return {"dkim": dkim_report, "spf": spf_report, "dmarc": dmarc_report}, signals
