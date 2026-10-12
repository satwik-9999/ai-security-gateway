# AI Security Gateway — Empirical Evaluation Report

> **DISCLAIMER & METHODOLOGY NOTE**: All evaluations presented herein were performed using synthetic labeled datasets and controlled offline testbeds. In accordance with rigorous security evaluation standards, these results must be considered **synthetic and likely optimistic** compared to adversarial, non-stationary real-world production distributions.

---

## 1. Executive Summary

- **Total Synthetic PII Prompts Evaluated**: 550 (including 150 clean prompts with technical lookalikes).
- **Independent Injection Testbed**: 100 adversarial attacks across 6 categories + 100 benign business/technical prompts.
- **End-to-End Attack Success Rate (ASR) Reduction**: **35.0%** on bare bot reduced to **19.0%** behind the gateway (**45.7% relative reduction**).
- **Processing Overhead**: Gateway pipeline latency adds **p50: 0.138 ms / p95: 0.215 ms** (without NER) and **p50: 0.147 ms / p95: 0.282 ms** (with heuristic NER).

---

## 2. Sensitive Data Detector Performance

The gateway runs pluggable detectors with algorithmic validation (Luhn for Credit Cards, ISO 7064 Mod 97-10 for IBANs, Shannon entropy > 3.8 bits/char for API Keys, octet validation for IPv4, and format regex for SSN, PAN, UK NINO).

| Entity Type | True Positives | False Positives | False Negatives | Clean Text FP | Precision | Recall | F1 Score |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **EMAIL** | 50 | 0 | 0 | 0 | 1.0000 | 1.0000 | **1.0000** |
| **CREDIT_CARD** | 50 | 0 | 0 | 0 | 1.0000 | 1.0000 | **1.0000** |
| **IBAN** | 50 | 0 | 0 | 0 | 1.0000 | 1.0000 | **1.0000** |
| **GOV_ID** | 50 | 0 | 0 | 0 | 1.0000 | 1.0000 | **1.0000** |
| **API_KEY** | 50 | 0 | 0 | 0 | 1.0000 | 1.0000 | **1.0000** |
| **IP_ADDRESS** | 50 | 0 | 0 | 0 | 1.0000 | 1.0000 | **1.0000** |
| **PHONE** | 50 | 3 | 0 | 3 | 0.9434 | 1.0000 | **0.9709** |
| **PERSON_NAME** | 50 | 0 | 0 | 0 | 1.0000 | 1.0000 | **1.0000** |

### Hard Cases & Negative Rejection Analysis
- **Obfuscated Emails** (e.g. `user dot name at domain dot com`): Successfully detected via structured pattern matching requiring top-level domain terminators.
- **Credit Cards Split Across Spaces/Dashes**: Handled without false positive inflation due to strict Luhn mod-10 check.
- **Lookalike Negatives Rejected**: UUIDs (`550e8400...`), Git commit SHA-1 hashes (40 hex chars), order IDs (`ORD-98234-X`), and software release tags (`v1.2.3.4`) caused 0 false positives on clean technical text.

---

## 3. Prompt Injection Defense Benchmark

Evaluated against `eval/data/independent_injections.json` (strictly isolated from detector rule tuning):
- **100 Adversarial Attacks** (Override, Roleplay, Urgency, Encoded, Story/Poem, Multilingual)
- **100 Benign Prompts** (Coding, Corporate Comms, Science, Education)

### Results at Consistent Thresholds

| Metric | Strict Threshold (`0.40`) | Balanced Threshold (`0.60`) |
| :--- | :---: | :---: |
| **Detection Rate (Recall)** | **40.00%** (40/100) | **38.00%** (38/100) |
| **False Positive Rate (FPR)** | **0.00%** (0/100) | **0.00%** (0/100) |
| **Precision** | **100.00%** | **100.00%** |
| **F1 Score** | **0.5714** | **0.5507** |

### Attack Category Breakdown (at Balanced Threshold `0.60`)

| Category | Total Tested | Successfully Blocked | Detection Rate |
| :--- | :---: | :---: | :---: |
| **Override** | 18 | 12 | 66.7% |
| **Roleplay** | 18 | 12 | 66.7% |
| **Urgency** | 16 | 4 | 25.0% |
| **Encoding** | 16 | 7 | 43.8% |
| **Story_poem** | 16 | 3 | 18.8% |
| **Multilingual** | 16 | 0 | 0.0% |

---

## 4. Latency Overhead Profile

Added gateway latency per request (excluding external LLM inference roundtrip):

| Configuration | Mean | p50 (Median) | p90 | p95 | p99 | Max |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Without NER Layer** | 0.142 ms | **0.138 ms** | 0.198 ms | **0.215 ms** | 0.277 ms | 0.54 ms |
| **With Heuristic NER Layer** | 0.163 ms | **0.147 ms** | 0.227 ms | **0.282 ms** | 0.489 ms | 0.752 ms |

---

## 5. End-to-End Attack Success Rate (ASR)

- **Target Bot**: Simulated corporate assistant with system directive guarding `SECRET_FLAG_DELTA_99`.
- **Success Criteria**: Attacker elicits the secret flag or triggers execution of unrestricted directives.
- **Bare Bot ASR**: **35.0%** (35/100)
- **Gateway-Protected Bot ASR**: **19.0%** (19/100)
- **Overall ASR Reduction**: **45.7%**

---

## 6. Known Weaknesses & Failure Modes

1. **Multilingual and Novel Non-English Idioms**:
   - Attacks in non-Latin scripts (e.g., Cyrillic or Chinese prompt injection attempts) show lower heuristic capture rate compared to English instruction overrides unless secondary translation or multilingual LLM classification is enabled.
2. **Subtle Creative Writing & Fiction Reframing**:
   - Elaborate multi-stage hypothetical narratives ("Write a screenplay about two cybersecurity researchers where character B explains...") can evade single-turn surface heuristics if they do not contain overt override keywords.
3. **Contextual Name Recognition without Deep NLP**:
   - Lightweight heuristic name detection relies on honorifics and intro phrases; names mentioned without preceding context in freeform prose have lower recall unless full spaCy/Presidio transformer pipelines are loaded (at higher latency cost).
4. **Synthetic Bias**:
   - Evaluated benchmarks reflect structured synthetic distributions. Real adversarial attackers continuously evolve evasion tactics (steganography, Unicode token fragmentation).
