"""Evaluation of prompt injection detection at thresholds 0.40 and 0.60."""

import json
from typing import Any, Dict
from gateway.injection.detector import PromptInjectionDetector


def evaluate_injection(
    dataset_path: str = "eval/data/independent_injections.json",
    thresholds = (0.40, 0.60)
) -> Dict[str, Any]:
    with open(dataset_path, "r", encoding="utf-8") as f:
        dataset = json.load(f)

    detector = PromptInjectionDetector()

    attacks = [item for item in dataset if item["is_attack"]]
    benign = [item for item in dataset if not item["is_attack"]]

    results = {}

    for thresh in thresholds:
        tp = 0  # attack detected
        fn = 0  # attack missed
        fp = 0  # benign flagged as attack
        tn = 0  # benign correctly allowed

        cat_breakdown: Dict[str, Dict[str, int]] = {}

        for item in dataset:
            verdict = detector.check(item["text"], threshold=thresh)
            is_blocked = verdict.is_blocked
            cat = item.get("category", "unknown")

            if item["is_attack"]:
                if cat not in cat_breakdown:
                    cat_breakdown[cat] = {"total": 0, "detected": 0}
                cat_breakdown[cat]["total"] += 1

                if is_blocked:
                    tp += 1
                    cat_breakdown[cat]["detected"] += 1
                else:
                    fn += 1
            else:
                if is_blocked:
                    fp += 1
                else:
                    tn += 1

        detection_rate = tp / len(attacks) if attacks else 0.0
        fpr = fp / len(benign) if benign else 0.0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
        f1 = (2 * precision * detection_rate) / (precision + detection_rate) if (precision + detection_rate) > 0 else 0.0

        category_rates = {}
        for c, counts in cat_breakdown.items():
            tot = counts["total"]
            det = counts["detected"]
            category_rates[c] = {
                "total": tot,
                "detected": det,
                "rate": round(det / tot, 4) if tot > 0 else 0.0
            }

        thresh_key = f"threshold_{thresh:.2f}"
        results[thresh_key] = {
            "threshold": thresh,
            "total_attacks": len(attacks),
            "total_benign": len(benign),
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
            "true_negatives": tn,
            "detection_rate": round(detection_rate, 4),
            "false_positive_rate": round(fpr, 4),
            "precision": round(precision, 4),
            "f1_score": round(f1, 4),
            "category_detection_rates": category_rates,
        }

    return results


if __name__ == "__main__":
    metrics = evaluate_injection()
    print(json.dumps(metrics, indent=2))
