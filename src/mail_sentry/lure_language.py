"""Multilingual lure phrase scoring.

Dictionaries live in ``lures/<language>.json``. Each term or regular
expression carries a weight. A category fires when the distinct terms it
matched add up to ``FIRE_SCORE``; a strong phrase has weight 2 and fires on
its own, a common word has weight 1 and needs company.

The message language is detected from the body (langdetect when installed,
otherwise a script and stopword heuristic) with ``Content-Language`` used to
confirm it. A confident result on a message of reasonable length scans that
language plus English. A weak result or a short message scans every
dictionary, because a sender controls the header and can mix languages to
dodge a single dictionary.
"""
from __future__ import annotations

import json
import re
import unicodedata
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

LURE_DIR = Path(__file__).with_name("lures")
FIRE_SCORE = 2
CONFIDENT = 0.6
DETECTION_SAMPLE = 20_000
# Below this length detection is unreliable and scanning every dictionary
# is cheap, so short messages are always scanned in full.
SHORT_TEXT = 400
CATEGORY_RULES = {
    "urgency": ("urgency_language", "Message uses urgency or account threat language common in lures"),
    "financial": ("payment_lure", "Message asks for money, bank details, or gift cards"),
    "invoice_payment": ("payment_lure", "Message pushes an unpaid invoice, failed payment, or fee"),
    "credential_reset": ("credential_lure", "Message pushes a password reset, expiry, or mailbox quota action"),
    "package_delivery": ("delivery_lure", "Message claims a held or failed parcel delivery"),
    "prize_lottery": ("prize_lure", "Message claims the reader won a prize or lottery"),
    "authority_impersonation": ("authority_lure", "Message invokes a tax office, police, or court"),
}
ARABIC_DIACRITICS = re.compile("[\u0610-\u061a\u064b-\u065f\u0670\u06d6-\u06ed\u0640]")
ARABIC_FOLD = str.maketrans({"\u0623": "\u0627", "\u0625": "\u0627", "\u0622": "\u0627", "\u0671": "\u0627", "\u0649": "\u064a", "\u0629": "\u0647"})
QUOTES = str.maketrans({"\u2019": "'", "\u2018": "'", "\u02bc": "'"})
SCRIPTS = (
    ("ja_kana", re.compile("[\u3040-\u30ff\u31f0-\u31ff\uff66-\uff9f]")),
    ("han", re.compile("[\u4e00-\u9fff\u3400-\u4dbf]")),
    ("arabic", re.compile("[\u0600-\u06ff\u0750-\u077f\ufb50-\ufdff\ufe70-\ufeff]")),
    ("cyrillic", re.compile("[\u0400-\u04ff]")),
    ("latin", re.compile("[A-Za-z\u00c0-\u024f]")),
)
WORD = re.compile(r"[^\W\d_]+")


@dataclass
class Dictionary:
    code: str
    name: str
    word_boundaries: bool
    fold_accents: bool
    stopwords: frozenset[str]
    categories: dict[str, list[tuple[str, re.Pattern, int]]] = field(default_factory=dict)


def _fold_script(text: str, code: str) -> str:
    if code == "ar":
        return ARABIC_DIACRITICS.sub("", text).translate(ARABIC_FOLD)
    if code == "ru":
        return text.replace("\u0451", "\u0435")  # yo to ye, as most Russian text does
    return text


def normalize(text: str, code: str, fold_accents: bool) -> str:
    text = unicodedata.normalize("NFKC", text).translate(QUOTES).casefold()
    if fold_accents:
        text = "".join(c for c in unicodedata.normalize("NFKD", text) if not unicodedata.combining(c))
    return re.sub(r"\s+", " ", _fold_script(text, code))


def _compile(entry: dict, code: str, word_boundaries: bool, fold_accents: bool) -> tuple[str, re.Pattern, int]:
    weight = entry.get("weight", 1)
    if isinstance(weight, bool) or not isinstance(weight, int) or not 1 <= weight <= 5:
        raise ValueError(f"lure weight for {entry} must be an integer from 1 to 5")
    if "pattern" in entry:
        label = entry["pattern"]
        # Patterns are written against normalized text: lower case, and
        # without accents for languages that fold them.
        body = _fold_script(entry["pattern"], code)
    else:
        label = entry["term"]
        # Normalized text has single spaces, so a term is a plain literal,
        # which lets the regex engine use its fast substring search.
        body = re.escape(normalize(entry["term"], code, fold_accents).strip())
    if word_boundaries:
        body = rf"(?:{body})(?!\w)" if "pattern" in entry else body + r"(?!\w)"
    return label, re.compile(body), weight


@lru_cache(maxsize=1)
def load_dictionaries() -> dict[str, Dictionary]:
    dictionaries = {}
    for path in sorted(LURE_DIR.glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        code = data["language"]
        dictionary = Dictionary(code, data.get("name", code), bool(data.get("word_boundaries", True)), bool(data.get("fold_accents", False)),
                                frozenset(normalize(w, code, bool(data.get("fold_accents"))) for w in data.get("stopwords", [])))
        for category, entries in data["categories"].items():
            if category not in CATEGORY_RULES:
                raise ValueError(f"{path.name}: unknown lure category {category}")
            dictionary.categories[category] = [_compile(e, code, dictionary.word_boundaries, dictionary.fold_accents) for e in entries]
        dictionaries[code] = dictionary
    return dictionaries


def _header_language(value: str) -> str:
    first = value.split(",")[0].strip().lower()
    return first.split("-")[0] if first else ""


def _builtin_detect(text: str) -> tuple[str, float]:
    counts = {name: len(pattern.findall(text)) for name, pattern in SCRIPTS}
    letters = sum(counts.values())
    if letters < 12:
        return "", 0.0
    if counts["ja_kana"] / letters > 0.05:
        return "ja", min(1.0, (counts["ja_kana"] + counts["han"]) / letters)
    for script, code in (("han", "zh"), ("arabic", "ar"), ("cyrillic", "ru")):
        share = counts[script] / letters
        if share > 0.3:
            return code, min(1.0, share + 0.1)
    if counts["latin"] / letters < 0.5:
        return "", 0.0
    hits: dict[str, int] = {}
    for dictionary in load_dictionaries().values():
        if not dictionary.stopwords:
            continue
        words = WORD.findall(normalize(text, dictionary.code, dictionary.fold_accents))
        hits[dictionary.code] = sum(1 for word in words if word in dictionary.stopwords)
    ranked = sorted(hits.items(), key=lambda item: -item[1])
    if not ranked or ranked[0][1] == 0:
        return "", 0.0
    top, top_hits = ranked[0]
    runner_up = ranked[1][1] if len(ranked) > 1 else 0
    margin = (top_hits - runner_up) / top_hits
    return top, round(min(1.0, top_hits / 4) * (0.5 + 0.5 * margin), 3)


def _langdetect(text: str) -> tuple[str, float] | None:
    try:
        from langdetect import DetectorFactory, detect_langs  # type: ignore
        from langdetect.lang_detect_exception import LangDetectException  # type: ignore
    except ImportError:
        return None
    DetectorFactory.seed = 0
    try:
        best = detect_langs(text)[0]
    except LangDetectException:
        return "", 0.0
    return best.lang.split("-")[0], round(best.prob, 3)


def detect_language(text: str, content_language: str = "", use_langdetect: bool = True) -> dict:
    sample = text[:DETECTION_SAMPLE]
    detected = _langdetect(sample) if use_langdetect else None
    method = "langdetect" if detected is not None else "builtin"
    language, confidence = detected if detected is not None else _builtin_detect(sample)
    header = _header_language(content_language)
    source = "body" if language else "none"
    if header and header == language:
        confidence = max(confidence, 0.9)
        source = "body+header"
    elif header and not language:
        # The header alone is a sender claim. Report it, but keep the
        # confidence low so every dictionary is still scanned.
        language, confidence, source = header, 0.4, "header"
    return {"detected": language or None, "confidence": round(confidence, 3), "source": source, "method": method, "content_language": header or None}


def _search(pattern: re.Pattern, text: str, bounded: bool) -> re.Match | None:
    """First match, requiring a non-word character before it when bounded.

    The left boundary is checked here instead of with a lookbehind, which
    would stop the engine from scanning ahead for the literal prefix.
    """
    for match in pattern.finditer(text):
        start = match.start()
        if not bounded or start == 0 or not (text[start - 1].isalnum() or text[start - 1] == "_"):
            return match
    return None


def scan_lures(text: str, content_language: str = "", use_langdetect: bool = True) -> tuple[list[dict], dict]:
    """Return (signals, language report) for visible text."""
    dictionaries = load_dictionaries()
    language = detect_language(text, content_language, use_langdetect)
    if len(text) >= SHORT_TEXT and language["detected"] in dictionaries and language["confidence"] >= CONFIDENT:
        scanned = list(dict.fromkeys([language["detected"], "en"]))
    else:
        scanned = list(dictionaries)
    language["scanned"] = scanned
    matches = []
    normalized_cache: dict[tuple[str, bool], str] = {}
    for code in scanned:
        dictionary = dictionaries[code]
        key = (code if code in {"ar", "ru"} else "", dictionary.fold_accents)
        if key not in normalized_cache:
            normalized_cache[key] = normalize(text, code, dictionary.fold_accents)
        normalized = normalized_cache[key]
        for category, terms in dictionary.categories.items():
            found = []
            score = 0
            for label, pattern, weight in terms:
                match = _search(pattern, normalized, dictionary.word_boundaries)
                if match:
                    found.append(match.group(0))
                    score += weight
            if score >= FIRE_SCORE:
                matches.append({"language": code, "category": category, "score": score, "terms": found[:5]})
    language["lure_matches"] = matches
    signals = []
    for match in matches:
        rule, detail = CATEGORY_RULES[match["category"]]
        prefix = "" if match["language"] == "en" else f"{dictionaries[match['language']].name}: "
        signals.append({"rule": rule, "detail": detail, "evidence": prefix + ", ".join(match["terms"])})
    return signals, language
