from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_rules(path: str | None = None) -> dict[str, Any]:
    source = Path(path) if path else Path(__file__).with_name("default_rules.json")
    try:
        data = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot load rules from {source}: {exc}") from exc
    return validate_rules(data)


def validate_rules(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise ValueError("rules configuration must be a JSON object")
    for section in ("weights", "thresholds", "limits", "domain_hints"):
        if section in data and not isinstance(data[section], dict):
            raise ValueError(f"rules.{section} must be an object")
    for section in ("trusted_domains", "shortener_domains", "suspicious_tlds", "dangerous_extensions", "trusted_authserv_ids"):
        if section in data and (not isinstance(data[section], list) or not all(isinstance(x, str) for x in data[section])):
            raise ValueError(f"rules.{section} must be a list of strings")
    for section in ("weights", "thresholds", "limits"):
        for name, value in data.get(section, {}).items():
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"rules.{section}.{name} must be a non-negative integer")
    thresholds = data.get("thresholds", {})
    values = [thresholds.get(k, default) for k, default in (("suspicious", 25), ("likely_phishing", 55), ("high_confidence", 80))]
    if values != sorted(values) or values[-1] > 100:
        raise ValueError("thresholds must be ordered and no greater than 100")
    limits = data.get("limits", {})
    for key, default in (("max_input_bytes", 25_000_000), ("max_mime_parts", 500), ("max_attachment_bytes", 15_000_000), ("max_archive_entries", 500), ("max_archive_uncompressed_bytes", 50_000_000), ("max_nested_url_depth", 2)):
        limits.setdefault(key, default)
    if limits["max_input_bytes"] < 1 or limits["max_mime_parts"] < 1 or limits["max_nested_url_depth"] > 5:
        raise ValueError("input and MIME limits must be positive; max_nested_url_depth cannot exceed 5")
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
