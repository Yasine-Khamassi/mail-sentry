from __future__ import annotations

MAX_EVIDENCE = 5


def score_signals(signals: list[dict], rules: dict) -> tuple[int, str, list[dict]]:
    """Group signals by rule and add each rule's weight once.

    Counting a rule once keeps a newsletter with forty tracking links from
    scoring like forty separate findings. Every occurrence is still counted
    and up to five evidence strings are kept for the analyst.
    """
    weights = rules.get("weights", {})
    grouped: dict[str, dict] = {}
    for signal in signals:
        rule = signal["rule"]
        entry = grouped.get(rule)
        if entry is None:
            entry = grouped[rule] = {"rule": rule, "weight": int(weights.get(rule, 0)), "detail": signal["detail"], "count": 0, "evidence": []}
        entry["count"] += 1
        evidence = signal.get("evidence")
        if evidence and evidence not in entry["evidence"] and len(entry["evidence"]) < MAX_EVIDENCE:
            entry["evidence"].append(evidence)
    weighted = sorted(grouped.values(), key=lambda s: (-s["weight"], s["rule"]))
    score = min(100, sum(s["weight"] for s in weighted))
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
