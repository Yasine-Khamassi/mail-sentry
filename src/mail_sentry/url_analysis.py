from __future__ import annotations

import html
import ipaddress
import posixpath
import re
import unicodedata
from urllib.parse import parse_qsl, unquote, urlsplit, urlunsplit

URL_RE = re.compile(r"(?i)\b(?:https?://|hxxps?://|www\.)[^\s<>\"'()]+")
ENCODED_URL_RE = re.compile(r"(?i)(?:https?%3a%2f%2f|https?:\\/\\/)[^\s\"'<>]+")
WRAPPER_KEYS = {"url", "u", "target", "dest", "destination", "redirect", "redirect_url", "redirect_uri", "continue", "next", "return", "returnurl", "return_to", "forward", "goto", "link", "q"}

# Characters that render as nothing and are used to split keywords or disguise
# links. ZWJ and ZWNJ are left out because Persian, Indic scripts, and emoji
# need them. Bidirectional controls are tracked separately.
INVISIBLE_CHARS = re.compile("[\u00ad\u180e\u200b\u2060-\u2064\ufeff]")
BIDI_CONTROLS = re.compile("[\u202a-\u202e\u2066-\u2069]")
# Browsers drop ASCII tab and newline anywhere in a URL.
URL_STRIP = re.compile("[\t\r\n]")
IDEOGRAPHIC_DOTS = str.maketrans({"\u3002": ".", "\uff0e": ".", "\uff61": "."})

# Common two label public suffixes. This is not the full Public Suffix List; it
# keeps registrable domain grouping sane for the most common ccTLD layouts.
MULTI_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "org.nz", "co.jp", "ne.jp", "or.jp", "co.kr", "or.kr",
    "com.br", "net.br", "org.br", "com.mx", "com.ar", "com.co", "com.tr",
    "com.cn", "net.cn", "org.cn", "com.hk", "com.sg", "com.my", "com.tw",
    "co.in", "net.in", "org.in", "co.za", "co.il", "com.sa", "com.eg",
    "co.id", "or.id", "com.ph", "com.vn", "com.pk", "com.ng", "co.ke",
    "co.ae", "net.ae", "org.ae", "gov.ae",
}

# Visual confusables folded to an ASCII skeleton before brand comparison: digit
# swaps, multi letter tricks, and the Cyrillic and Greek letters most often
# used in IDN homograph attacks.
_MULTI_CONFUSABLES = (("rn", "m"), ("vv", "w"))
_SINGLE_CONFUSABLES = str.maketrans({
    "0": "o", "1": "l", "3": "e", "5": "s", "7": "t", "8": "b", "9": "g", "|": "l", "!": "i",
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c", "\u0443": "y",
    "\u0445": "x", "\u0456": "i", "\u0458": "j", "\u04bb": "h", "\u0501": "d", "\u051b": "q",
    "\u0455": "s", "\u043a": "k", "\u043c": "m", "\u0442": "t", "\u0432": "b", "\u043d": "h",
    "\u03bf": "o", "\u03b1": "a", "\u03b5": "e", "\u03b9": "i", "\u03ba": "k", "\u03bd": "v",
    "\u03c1": "p", "\u03c4": "t", "\u03c5": "u", "\u03c7": "x", "\u0131": "i", "\u0261": "g",
})


def registrable_hint(host: str) -> str:
    """Approximate the registrable domain using a short multi label suffix list."""
    pieces = host.lower().rstrip(".").split(".")
    if len(pieces) >= 3 and ".".join(pieces[-2:]) in MULTI_LABEL_SUFFIXES:
        return ".".join(pieces[-3:])
    return ".".join(pieces[-2:]) if len(pieces) >= 2 else host.lower()


def _levenshtein(a: str, b: str) -> int:
    row = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        new = [i]
        for j, cb in enumerate(b, 1):
            new.append(min(new[-1] + 1, row[j] + 1, row[j - 1] + (ca != cb)))
        row = new
    return row[-1]


def skeleton(label: str) -> str:
    """Fold a domain label to a lowercase ASCII skeleton for homoglyph comparison."""
    text = unicodedata.normalize("NFKC", label).lower().translate(_SINGLE_CONFUSABLES)
    text = "".join(c for c in unicodedata.normalize("NFKD", text) if not unicodedata.combining(c))
    for source, target in _MULTI_CONFUSABLES:
        text = text.replace(source, target)
    return text


def _domain_stem(domain: str) -> str:
    registrable = registrable_hint(domain)
    suffix_labels = 2 if registrable.count(".") >= 2 else 1
    return ".".join(registrable.split(".")[:-suffix_labels]) or registrable


def unicode_host(host: str) -> str:
    """Decode punycode labels for display and homoglyph comparison."""
    labels = []
    for label in host.split("."):
        if label.startswith("xn--"):
            try:
                labels.append(label.encode("ascii").decode("idna"))
                continue
            except UnicodeError:
                pass
        labels.append(label)
    return ".".join(labels)


def lookalike(host: str, trusted: list[str]) -> str | None:
    """Return the trusted domain that ``host`` imitates, if any.

    Hosts inside a trusted domain never match. A match needs one of: the same
    homoglyph skeleton as the brand stem, an edit distance of one on a brand
    stem of five or more characters, or the brand stem appearing as its own
    label or hyphen separated token (``paypal-secure.example``).
    """
    host = unicode_host(host.lower().rstrip("."))
    for trusted_domain in trusted:
        target = registrable_hint(trusted_domain.lower())
        if host == target or host.endswith("." + target):
            return None
    stem = _domain_stem(host)
    stem_skeleton = skeleton(stem)
    host_tokens = {skeleton(token) for token in re.split(r"[.\-_]", host) if token}
    for trusted_domain in trusted:
        target_stem = _domain_stem(trusted_domain.lower())
        if len(target_stem) < 3:
            continue
        if stem_skeleton == target_stem:
            return trusted_domain
        if len(target_stem) >= 5 and len(stem) >= 4 and _levenshtein(stem_skeleton, target_stem) == 1:
            return trusted_domain
        if target_stem in host_tokens:
            return trusted_domain
    return None


def mixed_script(host: str) -> bool:
    """True when one label mixes Latin letters with Cyrillic or Greek letters."""
    for label in unicode_host(host).split("."):
        scripts = set()
        for char in label:
            if not char.isalpha():
                continue
            name = unicodedata.name(char, "")
            if name.startswith("LATIN"):
                scripts.add("latin")
            elif name.startswith("CYRILLIC"):
                scripts.add("cyrillic")
            elif name.startswith("GREEK"):
                scripts.add("greek")
        if "latin" in scripts and len(scripts) > 1:
            return True
    return False


def parse_ip_host(host: str) -> str | None:
    """Return a canonical IP for dotted, IPv6, or integer/hex/octal IPv4 hosts.

    Browsers accept ``http://3232235777/`` and ``http://0xc0.0xa8.1.1/`` as IPv4
    addresses, so those forms are decoded the same way.
    """
    candidate = host.strip("[]")
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        pass
    parts = host.split(".")
    if not parts or len(parts) > 4 or not all(parts):
        return None
    values = []
    for part in parts:
        try:
            if part.lower().startswith("0x"):
                values.append(int(part[2:] or "0", 16))
            elif len(part) > 1 and part.startswith("0"):
                values.append(int(part, 8))
            elif part.isdigit():
                values.append(int(part))
            else:
                return None
        except ValueError:
            return None
    if any(v > 255 for v in values[:-1]) or values[-1] >= 256 ** (5 - len(values)):
        return None
    number = values[-1]
    for index, value in enumerate(values[:-1]):
        number += value << (8 * (3 - index))
    return str(ipaddress.IPv4Address(number))


def clean_url(raw: str) -> str:
    """Apply the cleanup a browser performs before it parses a link."""
    value = html.unescape(raw).strip()
    value = URL_STRIP.sub("", value)
    value = INVISIBLE_CHARS.sub("", BIDI_CONTROLS.sub("", value))
    value = re.sub(r"(?i)^hxxp", "http", value)
    if re.match(r"(?i)^https?:", value):
        # http and https treat backslash as a path separator and accept any
        # number of slashes after the scheme.
        value = value.replace("\\", "/")
        value = re.sub(r"(?i)^(https?):/*", lambda m: m.group(1).lower() + "://", value)
    elif value.lower().startswith("www."):
        value = "http://" + value
    elif value.startswith("//"):
        value = "http:" + value
    return value


def normalize_url(raw: str) -> dict | None:
    """Return normalized URL parts, or None when no host can be parsed.

    Lowercases scheme and host, folds ideographic dots, decodes percent escapes
    in the host, converts the host to IDNA, drops default ports, and resolves
    dot segments and duplicate slashes in the path. Query and fragment are kept.
    """
    value = clean_url(raw)
    try:
        parsed = urlsplit(value if "://" in value else "http://" + value)
        hostname = parsed.hostname or ""
        port = parsed.port
        userinfo = parsed.username
    except ValueError:
        return None
    host = unquote(hostname).translate(IDEOGRAPHIC_DOTS).lower().rstrip(".")
    if not host or any(c in host for c in " /\\@"):
        return None
    try:
        ascii_host = host if host.isascii() else host.encode("idna").decode("ascii")
    except UnicodeError:
        ascii_host = host
    scheme = parsed.scheme.lower()
    netloc = f"[{ascii_host}]" if ":" in ascii_host else ascii_host
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        netloc += f":{port}"
    path = parsed.path
    if path:
        trailing = path.endswith("/")
        path = posixpath.normpath(re.sub(r"/{2,}", "/", path))
        if path.startswith("//"):
            path = path[1:]
        if path == ".":
            path = "/"
        if trailing and not path.endswith("/"):
            path += "/"
    return {"url": urlunsplit((scheme, netloc, path, parsed.query, parsed.fragment)), "host": ascii_host, "userinfo": userinfo}


def extract_urls(text: str) -> list[str]:
    cleaned = html.unescape(text).replace("\\/", "/")
    found = [m.group(0).rstrip(".,;:!?)\u201d\u2019]") for m in URL_RE.finditer(cleaned)]
    for match in ENCODED_URL_RE.finditer(text):
        decoded = unquote(match.group(0)).replace("\\/", "/").rstrip(".,;:!?)")
        if decoded not in found:
            found.append(decoded)
    return list(dict.fromkeys(clean_url(raw) for raw in found))


def unwrap(url: str, maximum_depth: int) -> list[str]:
    """Decode URLs carried in query or fragment parameters of wrapper links.

    This is string decoding only. It shows which URL a wrapper link names as
    its target. It does not show where an HTTP request would actually end up.
    """
    current = url
    found = []
    for _ in range(maximum_depth):
        try:
            parsed = urlsplit(current if "://" in current else "http://" + current)
            params = parse_qsl(parsed.query) + parse_qsl(parsed.fragment.lstrip("!/"))
        except ValueError:
            break
        candidate = None
        for key, value in params:
            value = html.unescape(unquote(value)).replace("\\/", "/").strip()
            if key.lower() in WRAPPER_KEYS and re.match(r"(?i)^(?:(?:https?|hxxps?):)?//|^www\.", value):
                candidate = clean_url(value)
                break
        if not candidate:
            break
        found.append(candidate)
        current = candidate
    return found


def host_obfuscation(raw: str) -> str | None:
    """Describe encoding tricks that change how the scheme or host reads."""
    lowered = raw.lower()
    without_scheme = re.sub(r"(?i)^[a-z][a-z0-9+.-]*:[/\\]*", "", raw)
    authority = re.split(r"[/\\?#]", without_scheme, maxsplit=1)[0]
    if "%" in authority:
        return "percent-encoded characters in the host or user info"
    if "%25" in lowered:
        return "double percent-encoding"
    if re.match(r"(?i)^https?:/*\\", raw):
        return "backslashes in place of slashes"
    if INVISIBLE_CHARS.search(raw) or BIDI_CONTROLS.search(raw):
        return "invisible or bidirectional control characters"
    if "\\u" in lowered or "\\x" in lowered:
        return "escaped characters"
    if URL_STRIP.search(raw.strip()):
        return "embedded tab or newline characters"
    if "&#" in raw:
        return "HTML character references inside the URL"
    return None


def analyze_urls(entries: list[tuple[str, str]], body_text: str, rules: dict) -> tuple[list[dict], list[dict]]:
    limits = rules.get("limits", {})
    max_urls = int(limits.get("max_urls", 500))
    nested_depth = int(limits.get("max_nested_url_depth", 2))
    shorteners = {d.lower() for d in rules.get("shortener_domains", [])}
    suspicious_tlds = {t.lower().lstrip(".") for t in rules.get("suspicious_tlds", [])}
    trusted = rules.get("trusted_domains", [])
    hints = {k.lower().rstrip("."): v for k, v in rules.get("domain_hints", {}).items()}
    age_threshold = int(rules.get("new_domain_days", 30))

    queue: list[tuple[str, str]] = []
    known: set[str] = set()
    for url, context in entries:
        url = url.strip()
        if url and url not in known:
            known.add(url)
            queue.append((url, context))
    for raw in extract_urls(body_text):
        if raw not in known:
            known.add(raw)
            queue.append((raw, "body"))

    inspected: list[dict] = []
    signals: list[dict] = []

    def add(rule: str, detail: str, evidence: str) -> None:
        signals.append({"rule": rule, "detail": detail, "evidence": evidence})

    index = 0
    while index < len(queue) and len(inspected) < max_urls:
        raw, context = queue[index]
        index += 1
        scheme = raw.split(":", 1)[0].strip().lower() if ":" in raw else ""
        if scheme == "data":
            media = raw.split(",", 1)[0][5:80]
            inspected.append({"url": raw[:200], "host": None, "context": context, "flags": ["data URI"], "media_type": media})
            if re.match(r"(?i)\s*(?:text/html|application/xhtml|image/svg|text/javascript|application/x?javascript)", media):
                add("data_uri_link", "Link or form target is an inline data: URI that renders content without a server", media)
            continue
        if scheme in {"javascript", "vbscript"}:
            inspected.append({"url": raw[:200], "host": None, "context": context, "flags": ["script URL"]})
            continue
        if scheme in {"mailto", "tel", "cid", "sms", "callto"}:
            continue

        normalized = normalize_url(raw)
        if not normalized:
            continue
        host = normalized["host"]
        display_host = unicode_host(host)
        registrable = registrable_hint(host)
        flags = []

        obfuscation = host_obfuscation(raw)
        if obfuscation:
            flags.append("obfuscated URL")
            add("obfuscated_url", f"URL uses {obfuscation}", raw[:200])
        if host.startswith("xn--") or ".xn--" in host:
            flags.append("punycode hostname")
            if mixed_script(host):
                flags.append("mixed-script hostname")
                add("punycode_domain", "IDN hostname mixes Latin with Cyrillic or Greek letters", f"{host} ({display_host})")
            else:
                add("punycode_domain", "URL hostname contains IDN punycode", f"{host} ({display_host})")
        if normalized["userinfo"]:
            flags.append("userinfo before hostname")
            add("url_userinfo", "URL puts user information before the host, so the text at the start is not the destination", raw[:200])
        ip = parse_ip_host(host)
        if ip:
            flags.append("IP literal")
            standard = host.strip("[]") == ip
            add("ip_url", "URL points directly to an IP address" + ("" if standard else " written in a non-standard notation"), f"{host} -> {ip}")
        if registrable in shorteners or host in shorteners:
            flags.append("URL shortener")
            add("shortener", "URL uses a known shortening service; its target is unknown without a live request", host)
        if not ip and host.rsplit(".", 1)[-1] in suspicious_tlds:
            flags.append("uncommon high-risk TLD")
            add("suspicious_tld", "URL uses a TLD often seen in low-cost abuse", host)
        brand = None if ip else lookalike(host, trusted)
        if brand:
            flags.append(f"resembles {brand}")
            add("lookalike_domain", f"URL domain resembles a trusted brand domain ({brand})", host if display_host == host else f"{host} ({display_host})")

        hint = hints.get(host) or hints.get(registrable) or {}
        age = hint.get("age_days")
        age_evidence = None
        if age is not None:
            age_evidence = {"age_days": age, "source": hint.get("source", "local configuration"), "method": "local domain_hints entry; no live registration lookup"}
            if age <= age_threshold:
                flags.append(f"domain age hint: {age} days")
                add("new_domain", f"Local metadata marks domain as {age} days old", f"{host}: age_days={age}; source={age_evidence['source']}")

        wrapped = unwrap(normalized["url"], nested_depth)
        if wrapped:
            flags.append("wrapper link names another URL")
            for target in wrapped:
                if target not in known:
                    known.add(target)
                    queue.append((target, "wrapped_target"))
        inspected.append({
            "url": raw[:2000],
            "normalized_url": normalized["url"][:2000],
            "host": host,
            "display_host": display_host,
            "registrable_domain": registrable,
            "context": context,
            "flags": list(dict.fromkeys(flags)),
            "wrapped_targets": wrapped,
            "domain_age": age_evidence,
        })
    if index < len(queue):
        add("analysis_limit", f"URL inspection stopped at the configured limit of {max_urls}", f"{len(queue)} URLs queued")
    return inspected, signals
