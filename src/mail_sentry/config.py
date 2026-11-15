from __future__ import annotations

import json
from pathlib import Path
from typing import Any

DEFAULT_RULES = Path(__file__).with_name("default_rules.json")
MERGED_SECTIONS = ("weights", "thresholds", "limits")
LIMIT_DEFAULTS = {
    "max_input_bytes": 25_000_000,
    "max_mime_parts": 500,
    "max_attachment_bytes": 15_000_000,
    "max_archive_entries": 500,
    "max_archive_members": 200,
    "max_archive_uncompressed_bytes": 50_000_000,
    "max_archive_depth": 2,
    "max_compression_ratio": 100,
    "max_nested_url_depth": 2,
    "max_urls": 500,
    "max_text_chars": 5_000_000,
}


def _read(source: Path) -> Any:
    try:
        return json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot load rules from {source}: {exc}") from exc


def load_rules(path: str | None = None) -> dict[str, Any]:
    """Load the default rules, then overlay a custom rules file if one is given.

    ``weights``, ``thresholds``, and ``limits`` are merged key by key, so a
    custom file only needs the values it changes. Every other key replaces the
    default value.
    """
    data = _read(DEFAULT_RULES)
    if path:
        custom = _read(Path(path))
        if not isinstance(custom, dict):
            raise ValueError("rules configuration must be a JSON object")
        for key, value in custom.items():
            if key in MERGED_SECTIONS and isinstance(value, dict) and isinstance(data.get(key), dict):
                data[key] = {**data[key], **value}
            else:
                data[key] = value
    return validate_rules(data)


def validate_rules(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise ValueError("rules configuration must be a JSON object")
    for section in ("weights", "thresholds", "limits", "domain_hints"):
        if section in data and not isinstance(data[section], dict):
            raise ValueError(f"rules.{section} must be an object")
    for section in ("trusted_domains", "shortener_domains", "suspicious_tlds", "dangerous_extensions", "trusted_authserv_ids", "trusted_receivers"):
        if section in data and (not isinstance(data[section], list) or not all(isinstance(x, str) for x in data[section])):
            raise ValueError(f"rules.{section} must be a list of strings")
    for section in MERGED_SECTIONS:
        for name, value in data.get(section, {}).items():
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"rules.{section}.{name} must be a non-negative integer")
    thresholds = data.get("thresholds", {})
    values = [thresholds.get(k, default) for k, default in (("suspicious", 25), ("likely_phishing", 55), ("high_confidence", 80))]
    if values != sorted(values) or values[-1] > 100:
        raise ValueError("thresholds must be ordered and no greater than 100")
    limits = data.setdefault("limits", {})
    for key, default in LIMIT_DEFAULTS.items():
        limits.setdefault(key, default)
    if limits["max_input_bytes"] < 1 or limits["max_mime_parts"] < 1 or limits["max_text_chars"] < 1:
        raise ValueError("input, MIME part, and text limits must be positive")
    if limits["max_nested_url_depth"] > 5 or limits["max_archive_depth"] > 5:
        raise ValueError("max_nested_url_depth and max_archive_depth cannot exceed 5")
    for host, hint in data.get("domain_hints", {}).items():
        if not isinstance(host, str) or not isinstance(hint, dict):
            raise ValueError("domain_hints must map host names to objects")
        age = hint.get("age_days")
        if age is not None and (isinstance(age, bool) or not isinstance(age, int) or age < 0):
            raise ValueError(f"domain_hints.{host}.age_days must be a non-negative integer")
    new_domain_days = data.get("new_domain_days", 30)
    if isinstance(new_domain_days, bool) or not isinstance(new_domain_days, int) or new_domain_days < 0:
        raise ValueError("new_domain_days must be a non-negative integer")
    return data
