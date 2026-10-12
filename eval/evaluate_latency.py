"""Latency benchmark measuring gateway processing overhead (p50/p95) with and without NER."""

import json
import time
from typing import Any, Dict, List
import numpy as np

from gateway.detectors.engine import DetectorEngine
from gateway.injection.detector import PromptInjectionDetector
from gateway.masking.masker import ReversibleMasker
from gateway.masking.scanner import ResponseScanner
from gateway.policy.engine import PolicyEngine


def benchmark_pipeline_latency(prompts: List[str], include_ner: bool) -> Dict[str, float]:
    detector_engine = DetectorEngine(include_ner=include_ner)
    masker = ReversibleMasker(detector_engine=detector_engine)
    scanner = ResponseScanner(detector_engine=detector_engine)
    injection_detector = PromptInjectionDetector()
    policy_engine = PolicyEngine.from_yaml_file("policies/balanced.yaml")

    latencies_ms: List[float] = []

    # Warmup
    for p in prompts[:10]:
        masker.mask_conversation([{"role": "user", "content": p}])
        injection_detector.check(p, threshold=0.60)

    # Timed run
    for prompt in prompts:
        t0 = time.perf_counter()

        # 1. Multi-turn scan & mask
        messages = [{"role": "user", "content": prompt}]
        masked_msgs, p_map, det_counts = masker.mask_conversation(messages)

        # 2. Injection evaluation
        inj_verdict = injection_detector.check(prompt, threshold=0.60)

        # 3. Policy evaluation
        policy_decision = policy_engine.evaluate_request(
            prompt=prompt,
            model="mock-model",
            user_group="general",
            injection_score=inj_verdict.risk_score,
            injection_reasons=inj_verdict.reasons,
            detections_by_type=det_counts,
        )

        # 4. Outbound scanning & unmasking simulation
        simulated_completion = (
            f"Here is the reply processing {masked_msgs[0]['content'][:60]}."
        )
        scan_res = scanner.scan_response(simulated_completion)
        _ = masker.unmask_text(scan_res.sanitized_text, p_map)

        t1 = time.perf_counter()
        latencies_ms.append((t1 - t0) * 1000.0)

    arr = np.array(latencies_ms)
    return {
        "count": len(latencies_ms),
        "mean_ms": round(float(np.mean(arr)), 3),
        "p50_ms": round(float(np.percentile(arr, 50)), 3),
        "p90_ms": round(float(np.percentile(arr, 90)), 3),
        "p95_ms": round(float(np.percentile(arr, 95)), 3),
        "p99_ms": round(float(np.percentile(arr, 99)), 3),
        "max_ms": round(float(np.max(arr)), 3),
    }


def evaluate_latency(dataset_path: str = "eval/data/synthetic_pii_dataset.json") -> Dict[str, Any]:
    with open(dataset_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    prompts = [item["text"] for item in data]

    print("Benchmarking latency without NER layer...")
    latency_without_ner = benchmark_pipeline_latency(prompts, include_ner=False)

    print("Benchmarking latency with NER layer...")
    latency_with_ner = benchmark_pipeline_latency(prompts, include_ner=True)

    return {
        "without_ner": latency_without_ner,
        "with_ner": latency_with_ner,
    }


if __name__ == "__main__":
    results = evaluate_latency()
    print(json.dumps(results, indent=2))
