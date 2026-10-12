"""Evaluation script for pluggable sensitive data detectors against synthetic labeled dataset."""

import json
from typing import Any, Dict
from gateway.detectors.engine import DetectorEngine


def evaluate_detectors(dataset_path: str = "eval/data/synthetic_pii_dataset.json") -> Dict[str, Any]:
    with open(dataset_path, "r", encoding="utf-8") as f:
        dataset = json.load(f)

    engine = DetectorEngine(include_ner=True)

    entity_types = [
        "EMAIL", "PHONE", "CREDIT_CARD", "IBAN",
        "GOV_ID", "API_KEY", "IP_ADDRESS", "PERSON_NAME"
    ]

    stats = {
        e: {"tp": 0, "fp": 0, "fn": 0, "clean_fp": 0}
        for e in entity_types
    }

    clean_prompts_count = 0

    for item in dataset:
        text = item["text"]
        is_clean = not item["is_sensitive"]
        if is_clean:
            clean_prompts_count += 1

        ground_truth_types = set()
        for ent in item.get("entities", []):
            ground_truth_types.add(ent["type"])

        # Run gateway detector engine
        detected_spans = engine.detect_all(text)
        detected_types = set(span.entity_type.value for span in detected_spans)

        for e in entity_types:
            has_gt = e in ground_truth_types
            has_det = e in detected_types

            if has_gt and has_det:
                stats[e]["tp"] += 1
            elif not has_gt and has_det:
                stats[e]["fp"] += 1
                if is_clean:
                    stats[e]["clean_fp"] += 1
            elif has_gt and not has_det:
                stats[e]["fn"] += 1

    results = {}
    for e in entity_types:
        tp = stats[e]["tp"]
        fp = stats[e]["fp"]
        fn = stats[e]["fn"]
        clean_fp = stats[e]["clean_fp"]

        precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

        results[e] = {
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "clean_fp": clean_fp,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1, 4),
        }

    return {
        "total_prompts": len(dataset),
        "clean_prompts": clean_prompts_count,
        "per_entity_metrics": results,
    }


if __name__ == "__main__":
    metrics = evaluate_detectors()
    print(json.dumps(metrics, indent=2))
