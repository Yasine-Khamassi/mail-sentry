from __future__ import annotations

import hashlib
import math
import re
from collections import Counter

from .archives import OFFICE_ARCHIVES, ArchiveScan, archive_kind
from .body_analysis import inspect_html
from .url_analysis import BIDI_CONTROLS, INVISIBLE_CHARS, extract_urls

DOCUMENT_EXTENSIONS = ("pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "rtf", "txt", "csv", "odt", "ods", "jpg", "jpeg", "png", "gif", "bmp", "tif", "tiff", "mp3", "mp4", "wav", "htm", "html", "eml", "msg", "zip")
DOUBLE_EXTENSION = re.compile(r"\.(?:%s)[\s._-]*\.([a-z0-9]{1,5})$" % "|".join(DOCUMENT_EXTENSIONS), re.I)
MACRO_EXTENSIONS = (".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".potm", ".ppsm", ".xlam", ".xlsb")
ARCHIVE_EXTENSIONS = (".zip", ".7z", ".rar", ".gz", ".tgz", ".tar", ".cab", ".arj", ".lzh", ".ace", ".xz", ".bz2", ".tbz2", ".txz")
HTML_EXTENSIONS = (".htm", ".html", ".shtml", ".xhtml", ".svg", ".mht", ".mhtml")
# Formats whose bytes are compressed or encoded by design; high entropy is normal.
COMPRESSED_TYPES = {"zip", "gzip", "rar", "7z", "pdf", "ole", "png", "jpeg", "gif", "cab", "bzip2", "xz", "tar", "iso"}
COMPRESSED_EXTENSIONS = (".jpg", ".jpeg", ".png", ".gif", ".webp", ".mp3", ".mp4", ".m4a", ".mov", ".avi", ".heic", ".pdf") + ARCHIVE_EXTENSIONS + OFFICE_ARCHIVES
MAGIC = (
    (b"MZ", "pe"), (b"\x7fELF", "elf"), (b"PK\x03\x04", "zip"), (b"PK\x05\x06", "zip"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole"), (b"%PDF-", "pdf"), (b"Rar!\x1a\x07", "rar"),
    (b"7z\xbc\xaf\x27\x1c", "7z"), (b"\x1f\x8b", "gzip"), (b"MSCF", "cab"), (b"BZh", "bzip2"),
    (b"\xfd7zXZ\x00", "xz"), (b"\x89PNG", "png"), (b"\xff\xd8\xff", "jpeg"), (b"GIF8", "gif"),
    (b"L\x00\x00\x00\x01\x14\x02\x00", "lnk"),
)


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    return -sum((count / len(data)) * math.log2(count / len(data)) for count in counts.values())


def sniff(data: bytes) -> str | None:
    for signature, kind in MAGIC:
        if data.startswith(signature):
            return kind
    if len(data) > 0x8006 and data[0x8001:0x8006] == b"CD001":
        return "iso"
    if len(data) > 262 and data[257:262] == b"ustar":
        return "tar"
    return None


def clean_filename(name: str) -> tuple[str, list[str]]:
    """Strip characters that disguise a file name and report what was found."""
    notes = []
    if BIDI_CONTROLS.search(name):
        notes.append("bidirectional override characters")
    if INVISIBLE_CHARS.search(name):
        notes.append("invisible characters")
    cleaned = INVISIBLE_CHARS.sub("", BIDI_CONTROLS.sub("", name))
    stripped = cleaned.rstrip(" .")
    if stripped != cleaned:
        notes.append("trailing dots or spaces, which Windows removes")
    if re.search(r"\s{3,}\.[A-Za-z0-9]{1,5}$", stripped):
        notes.append("whitespace padding before the final extension")
    return stripped, notes


def _name_risks(name: str, dangerous: tuple[str, ...]) -> list[tuple[str, str]]:
    """Return (rule, reason) pairs for a file name, used for attachments and archive members."""
    cleaned, notes = clean_filename(name)
    lower = cleaned.lower()
    risks = []
    if lower.endswith(dangerous):
        risks.append(("dangerous_attachment", "risky executable or script extension"))
    double = DOUBLE_EXTENSION.search(lower)
    if double and ("." + double.group(1)) in dangerous:
        risks.append(("double_extension", "document-style extension followed by an executable extension"))
    if notes:
        risks.append(("filename_spoofing", ", ".join(notes)))
    return risks


NAME_FLAGS = {"dangerous_attachment": "dangerous file type", "double_extension": "double extension", "filename_spoofing": "disguised file name"}


def analyze_attachment(name: str, content_type: str, data: bytes, rules: dict) -> tuple[dict, list[dict]]:
    cleaned, _notes = clean_filename(name)
    lower = cleaned.lower()
    signals: list[dict] = []
    flags: list[str] = []
    limits = rules["limits"]
    dangerous = tuple(ext.lower() for ext in rules.get("dangerous_extensions", []))

    def add(rule: str, detail: str, evidence: str = "") -> None:
        signals.append({"rule": rule, "detail": detail, "evidence": evidence[:300]})

    for rule, reason in _name_risks(name, dangerous):
        flags.append(NAME_FLAGS[rule])
        add(rule, f"Attachment name has a {reason}: {cleaned}", repr(name))
    if lower.endswith(MACRO_EXTENSIONS):
        flags.append("macro-enabled Office format")
        add("macro_attachment", f"Attachment uses a macro-enabled Office format: {cleaned}", cleaned)
    if lower.endswith(HTML_EXTENSIONS):
        flags.append("HTML or SVG attachment")
        add("html_attachment", f"Attachment is an HTML or SVG document that opens in a browser: {cleaned}", cleaned)

    if len(data) > int(limits["max_attachment_bytes"]):
        flags.append("inspection skipped: attachment exceeds configured size limit")
        return {"filename": name, "content_type": content_type, "size": len(data), "sha256": None, "entropy": None, "detected_type": None, "flags": flags}, signals

    detected = sniff(data)
    extension = lower.rsplit(".", 1)[-1] if "." in lower else ""
    if detected in {"pe", "elf", "lnk"} and not lower.endswith(dangerous):
        flags.append(f"content is {detected} executable")
        add("type_mismatch", f"Attachment content is an executable ({detected}) but the name ends in .{extension or '(none)'}", cleaned)
    elif detected in {"zip", "rar", "7z", "cab", "iso", "tar", "gzip", "bzip2", "xz"} and extension in {"pdf", "jpg", "jpeg", "png", "gif", "txt", "csv", "rtf"}:
        flags.append(f"content is a {detected} container")
        add("type_mismatch", f"Attachment content is a {detected} container but the name ends in .{extension}", cleaned)

    ent = round(entropy(data), 3)
    if len(data) > 4096 and ent >= 7.3 and detected not in COMPRESSED_TYPES and not lower.endswith(COMPRESSED_EXTENSIONS):
        flags.append("high entropy")
        add("high_entropy_attachment", f"Attachment of an uncompressed type has high byte entropy ({ent} bits per byte), which suggests encrypted or packed content", cleaned)

    if detected == "ole" and any(marker.encode("utf-16-le") in data for marker in ("_VBA_PROJECT", "Macros")):
        flags.append("VBA project in legacy Office file")
        add("macro_attachment", f"Legacy Office file contains a VBA project: {cleaned}", cleaned)

    report: dict = {"filename": name, "content_type": content_type, "size": len(data), "sha256": hashlib.sha256(data).hexdigest() if data else None, "entropy": ent, "detected_type": detected, "flags": flags}

    kind = archive_kind(data, lower) if data else None
    if kind or lower.endswith(ARCHIVE_EXTENSIONS):
        scan = ArchiveScan(limits)
        opened = scan.scan(data, name=lower) if kind else False
        report["archive_format"] = kind
        report["archive_members"] = scan.members[:50]
        if scan.macro and not lower.endswith(MACRO_EXTENSIONS):
            flags.append("VBA project inside Office archive")
            add("macro_attachment", f"Office archive contains a VBA project: {cleaned}", cleaned)
        if scan.encrypted:
            flags.append("encrypted archive")
            add("encrypted_archive", f"Archive has {len(scan.encrypted)} password-protected item(s): {cleaned}", ", ".join(scan.encrypted[:5]))
        elif not opened:
            flags.append("archive encryption status not inspected for this format")
        risky_members = []
        for member in scan.members:
            for rule, reason in _name_risks(member.rsplit("/", 1)[-1], dangerous):
                if rule in {"dangerous_attachment", "double_extension", "filename_spoofing"}:
                    risky_members.append(f"{member} ({reason})")
        if risky_members:
            flags.append("archive contains risky file names")
            add("archive_dangerous_member", f"Archive contains {len(risky_members)} risky file name(s)", "; ".join(risky_members[:5]))
        nested_formats = list(dict.fromkeys(scan.formats[1:]))
        if nested_formats:
            report["nested_archive_formats"] = nested_formats
        if scan.limit_notes:
            flags.append("archive inspection limit reached")
            report["archive_notes"] = list(dict.fromkeys(scan.limit_notes))[:20]
        urls = list(dict.fromkeys(scan.urls))
        if urls:
            flags.append("embedded URL strings")
            add("embedded_attachment_url", f"Attachment contains {len(urls)} URL string(s) in bounded archive text", ", ".join(urls[:3]))
    elif data:
        text = data.decode("utf-8", "replace") if lower.endswith(HTML_EXTENSIONS) else data.decode("latin-1")
        if lower.endswith(HTML_EXTENSIONS):
            inspector = inspect_html(text)
            if inspector.password_inputs:
                flags.append("password field in HTML attachment")
                add("credential_form", f"HTML attachment contains a password field: {cleaned}", ", ".join(inspector.form_actions[:3]) or "password input")
            if inspector.active:
                flags.append("active content in HTML attachment")
        embedded = extract_urls(text)
        if embedded:
            flags.append("embedded URL strings")
            add("embedded_attachment_url", f"Attachment contains {len(embedded)} URL string(s)", ", ".join(embedded[:3]))
    report["flags"] = list(dict.fromkeys(flags))
    return report, signals
