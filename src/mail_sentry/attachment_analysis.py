from __future__ import annotations

import hashlib
import io
import math
import re
import zipfile
from collections import Counter
from pathlib import Path

from .url_analysis import extract_urls


DOUBLE_EXTENSION = re.compile(r"\.(?:pdf|docx?|xlsx?|jpg|png|txt)\.(?:exe|scr|js|vbs|bat|cmd|com)$", re.I)
OFFICE_ARCHIVES = {".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm"}


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    return -sum((count / len(data)) * math.log2(count / len(data)) for count in counts.values())


def _archive_urls(data: bytes, limits: dict) -> tuple[list[str], bool, bool]:
    """Return URLs found in bounded textual archive members, encrypted and limit flags."""
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
        entries = archive.infolist()
    except (zipfile.BadZipFile, OSError, ValueError):
        return [], False, False
    if any(info.flag_bits & 1 for info in entries):
        return [], True, False
    if len(entries) > limits["max_archive_entries"] or sum(x.file_size for x in entries) > limits["max_archive_uncompressed_bytes"]:
        return [], False, True
    found: list[str] = []
    budget = int(limits["max_archive_uncompressed_bytes"])
    for info in entries:
        if info.is_dir() or info.file_size > budget or info.file_size > 2_000_000:
            continue
        name = info.filename.lower()
        if not name.endswith((".xml", ".rels", ".txt", ".html", ".htm")):
            continue
        try:
            with archive.open(info) as stream:
                content = stream.read(min(info.file_size, budget) + 1)
            if len(content) > budget:
                return found, False, True
            found.extend(extract_urls(content.decode("utf-8", "replace")))
            budget -= len(content)
        except (RuntimeError, zipfile.BadZipFile, OSError):
            continue
    return list(dict.fromkeys(found)), False, False


def analyze_attachment(name: str, content_type: str, data: bytes, rules: dict) -> tuple[dict, list[dict]]:
    lower = name.lower()
    signals: list[dict] = []
    flags: list[str] = []
    limits = rules["limits"]
    maximum = int(limits["max_attachment_bytes"])

    def add(rule: str, detail: str, evidence: str = "") -> None:
        signals.append({"rule": rule, "detail": detail, "evidence": evidence})

    if any(lower.endswith(ext.lower()) for ext in rules.get("dangerous_extensions", [])):
        flags.append("dangerous file type")
        add("dangerous_attachment", f"Attachment has a risky executable or script extension: {name}", name)
    if DOUBLE_EXTENSION.search(lower):
        flags.append("double extension")
        add("double_extension", f"Attachment uses a deceptive double extension: {name}", name)
    if lower.endswith((".docm", ".xlsm", ".pptm")):
        flags.append("macro-enabled Office format")
        add("macro_attachment", f"Attachment may contain Office macros: {name}", name)
    if len(data) > maximum:
        flags.append("inspection skipped: attachment exceeds configured size limit")
        return ({"filename": name, "content_type": content_type, "size": len(data), "sha256": None, "entropy": None, "flags": flags}, signals)
    ent = round(entropy(data), 3) if data else 0.0
    if len(data) > 4096 and ent >= 7.3:
        flags.append("high entropy")
        add("high_entropy_attachment", f"Attachment has high byte entropy ({ent} bits per byte): {name}", name)
    if lower.endswith((".zip", ".7z", ".rar") + tuple(OFFICE_ARCHIVES)) and data:
        encrypted = False
        limit_hit = False
        if lower.endswith((".zip",) + tuple(OFFICE_ARCHIVES)):
            embedded, encrypted, limit_hit = _archive_urls(data, limits)
        elif lower.endswith(".7z"):
            flags.append("archive encryption status not inspected for this format")
            embedded = []
        else:
            flags.append("archive encryption status not inspected for this format")
            embedded = []
        if encrypted:
            flags.append("encrypted archive")
            add("encrypted_archive", f"Archive appears encrypted or password protected: {name}", name)
        if limit_hit:
            flags.append("archive inspection limit reached")
        if embedded:
            flags.append("embedded URL strings")
            add("embedded_attachment_url", f"Attachment contains {len(embedded)} URL string(s) in bounded archive text", ", ".join(embedded[:3]))
    else:
        embedded = extract_urls(data.decode("latin-1", "ignore")) if data else []
        if embedded:
            flags.append("embedded URL strings")
            add("embedded_attachment_url", f"Attachment contains {len(embedded)} URL string(s)", ", ".join(embedded[:3]))
    result = {"filename": name, "content_type": content_type, "size": len(data), "sha256": hashlib.sha256(data).hexdigest() if data else None, "entropy": ent, "flags": flags}
    return result, signals
