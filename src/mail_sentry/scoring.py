from __future__ import annotations


def score_signals(signals: list[dict], rules: dict) -> tuple[int, str, list[dict]]:
    weighted = []
    for signal in signals:
        weight = int(rules.get("weights", {}).get(signal["rule"], 0))
        weighted.append({**signal, "weight": weight})
    score = min(100, sum(signal["weight"] for signal in weighted))
    thresholds = rules.get("thresholds", {})
    if score >= int(thresholds.get("high_confidence", 80)):
        verdict = "high_confidence_phishing"
    elif score >= int(thresholds.get("likely_phishing", 55)):
        verdict = "likely_phishing"
    elif score >= int(thresholds.get("suspicious", 25)):
        verdict = "suspicious"
    else:
        verdict = "low_risk"
    return score, verdict, weighted
