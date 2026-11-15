from __future__ import annotations

import html
import re
from urllib.parse import parse_qs, unquote, urlsplit

from .body_analysis import ZERO_WIDTH

URL_RE = re.compile(r"(?i)\b(?:https?://|hxxps?://|www\.)[^\s<>\"'()]+")
ENCODED_URL_RE = re.compile(r"(?i)(?:https?%3a%2f%2f|https?:\\/\\/)[^\s\"'<>]+")
WRAPPER_KEYS = {"url", "u", "target", "dest", "destination", "redirect", "redirect_url", "continue", "next", "return", "returnurl", "forward"}


def registrable_hint(host: str) -> str:
    pieces = host.lower().rstrip(".").split(".")
    return ".".join(pieces[-2:]) if len(pieces) >= 2 else host.lower()


def _levenshtein(a: str, b: str) -> int:
    row = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        new = [i]
        for j, cb in enumerate(b, 1):
            new.append(min(new[-1] + 1, row[j] + 1, row[j - 1] + (ca != cb)))
        row = new
    return row[-1]


def _lookalike(host: str, trusted: list[str]) -> str | None:
    domain = registrable_hint(host)
    for trusted_domain in trusted:
        target = registrable_hint(trusted_domain)
        if domain == target or domain.endswith("." + target):
            continue
        stem = domain.partition(".")[0]
        target_stem = target.partition(".")[0]
        if len(stem) >= 4 and (_levenshtein(stem, target_stem) <= 1 or target_stem in stem or stem in target_stem):
            return trusted_domain
    return None


def extract_urls(text: str) -> list[str]:
    cleaned = html.unescape(text).replace("\\/", "/")
    found = [m.group(0).rstrip(".,;:!?)\u201d\u2019]") for m in URL_RE.finditer(cleaned)]
    for match in ENCODED_URL_RE.finditer(text):
        decoded = unquote(match.group(0)).replace("\\/", "/").rstrip(".,;:!?)")
        if decoded not in found:
            found.append(decoded)
    result = []
    for raw in found:
        value = raw.replace("hxxp", "http")
        if value.lower().startswith("www."):
            value = "http://" + value
        result.append(value)
    return list(dict.fromkeys(result))


def _unwrap(raw: str, maximum_depth: int) -> list[str]:
    current = raw
    found = []
    for _ in range(maximum_depth):
        try:
            parsed = urlsplit(current if "://" in current else "http://" + current)
            query = parse_qs(parsed.query, keep_blank_values=False)
        except ValueError:
            break
        candidate = next((v[0] for k, v in query.items() if k.lower() in WRAPPER_KEYS and v), None)
        if not candidate:
            break
        candidate = html.unescape(unquote(candidate)).replace("\\/", "/")
        if not re.match(r"(?i)^https?://", candidate):
            break
        found.append(candidate)
        current = candidate
    return found


def analyze_urls(entries: list[tuple[str, str]], body_text: str, rules: dict) -> tuple[list[dict], list[dict]]:
    from urllib.parse import unquote

    all_entries = [(html.unescape(url).strip(), context) for url, context in entries if url.strip()]
    for raw in extract_urls(body_text):
        if not any(existing == raw for existing, _ in all_entries):
            all_entries.append((raw, "body"))
    inspected = []
    signals = []
    seen = set()
    nested_depth = int(rules.get("limits", {}).get("max_nested_url_depth", 2))
    index = 0
    while index < len(all_entries):
        raw, context = all_entries[index]
        index += 1
        try:
            canonical = unquote(raw.strip())
            parsed = urlsplit(canonical if "://" in canonical else "http://" + canonical)
            host = (parsed.hostname or "").lower().rstrip(".")
        except ValueError:
            continue
        if not host:
            continue
        flags = []
        def add(rule: str, detail: str, evidence: str) -> None:
            signals.append({"rule": rule, "detail": detail, "evidence": evidence})
        if "%" in raw or "\\u" in raw.lower() or ZERO_WIDTH.search(raw):
            flags.append("encoded or obfuscated URL")
            add("obfuscated_url", "URL contains encoding or obfuscation markers", raw)
        try:
            host.encode("ascii")
        except UnicodeEncodeError:
            flags.append("unicode hostname")
        try:
            ascii_host = host.encode("idna").decode("ascii")
        except UnicodeError:
            ascii_host = host
        if ascii_host.startswith("xn--") or ".xn--" in ascii_host:
            flags.append("punycode hostname")
            add("punycode_domain", "URL hostname contains IDN punycode", ascii_host)
        if parsed.username or parsed.password:
            flags.append("userinfo before hostname")
            add("url_userinfo", "URL embeds user information before its host", raw)
        if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host):
            flags.append("IP literal")
            add("ip_url", "URL points directly to an IPv4 address", host)
        if registrable_hint(host) in set(rules.get("shortener_domains", [])):
            flags.append("URL shortener")
            add("shortener", "URL uses a known shortening service; final destination was not fetched", host)
        if host.split(".")[-1] in set(rules.get("suspicious_tlds", [])):
            flags.append("uncommon high-risk TLD")
            add("suspicious_tld", "URL uses a TLD often seen in low-cost abuse", host)
        lookalike = _lookalike(host, rules.get("trusted_domains", []))
        if lookalike:
            flags.append(f"resembles {lookalike}")
            add("lookalike_domain", f"URL domain resembles a trusted brand domain ({lookalike})", host)
        hints = {k.lower().rstrip("."): v for k, v in rules.get("domain_hints", {}).items()}
        hint = hints.get(host) or hints.get(registrable_hint(host)) or {}
        age = hint.get("age_days")
        age_threshold = int(rules.get("new_domain_days", 30))
        age_evidence = None
        if age is not None:
            age_evidence = {"age_days": age, "source": hint.get("source", "local configuration")}
            if age <= age_threshold:
                flags.append(f"domain age hint: {age} days")
                add("new_domain", f"Local metadata marks domain as {age} days old", f"{host}: age_days={age}; source={age_evidence['source']}")
        nested = _unwrap(raw, nested_depth)
        if nested:
            flags.append("redirect wrapper contains nested URL")
            for destination in nested:
                if not any(existing == destination for existing, _ in all_entries):
                    all_entries.append((destination, "redirect_target"))
        key = (raw, context)
        if key in seen:
            continue
        inspected.append({"url": raw, "host": host, "context": context, "flags": list(dict.fromkeys(flags)), "redirect_destination": nested[0] if nested else None, "nested_destinations": nested[1:], "domain_age": age_evidence})
        seen.add(key)
    return inspected, signals
