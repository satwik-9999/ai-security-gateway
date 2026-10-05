# AI Security Gateway - Implementation Plan

## 1. System Architecture

The **AI Security Gateway** is a reverse proxy and policy enforcement point positioned between internal clients (employees, internal applications) and Large Language Model (LLM) providers. It significantly reduces the risk of data loss prevention (DLP) violations and prompt-injection attacks without relying solely on the external model's internal alignment.

```
Client (Employee / App)
         │
         ▼
[ FastAPI Gateway API (/v1/chat) ]
         │
         ├───► [ 1. Policy Lookup & Quota Check ] (User/Group, Max tokens, Allowed models)
         │
         ├───► [ 2. Inbound Sensitive Data Detection across ALL messages ] 
         │           (Email, Phone, CC, IBAN, Gov ID [SSN, PAN, UK NINO], API Keys, IP, Names)
         │
         ├───► [ 3. Prompt-Injection Detection ] (Heuristic layers + Optional Classifier)
         │
         ├───► [ 4. Policy Decision Engine ] (ALLOW / MASK / BLOCK)
         │           ├── If BLOCK ───────► Return 403 Forbidden with security reason
         │           └── If MASK ────────► [ Reversible In-Memory Masker ] (<EMAIL_1>, etc. consistent across turns)
         │
         ├───► [ 5. LLM Provider Dispatch ] (MockProvider offline / Gemini gemini-2.5-flash-lite)
         │
         ├───► [ 6. Response Scanning & Restoration ] (Scan output for leaks + unmask placeholders)
         │
         └───► [ 7. SQLite Audit Logging ] (Salted hash of prompt, detection counts ONLY, latency, decision)
         │
         ▼
Client receives sanitized, restored response
```

---

## 2. Threat Model & Security Boundaries

### 2.1 What the Gateway Defends Against
1. **Accidental PII / Secret Leakage**:
   - Employees inadvertently copying customer names, credit card numbers, IBANs, SSNs/national IDs, phone numbers, email addresses, or high-entropy API keys (OpenAI keys, GitHub tokens, AWS access keys) into AI prompts.
2. **Direct Prompt Injections (Jailbreaks)**:
   - "Ignore previous instructions", role-playing escalations ("DAN", "Developer Mode"), simulated terminals, encoded attacks (Base64, Hex, ROT13), system prompt extraction attempts, and urgency/authority manipulation.
3. **Model Exfiltration / Output Secret Leakage**:
   - Model completions echoing back sensitive data from context that violate company data governance policies.
4. **Audit Log Privacy**:
   - Privacy-preserving logging: Audit logs must never become a secondary honey-pot of leaked credentials. Raw prompts and detected values are never written to disk; only salted cryptographic digests (SHA-256) and aggregate token counts are stored.

### 2.2 What is Out of Scope (Known Limits)
- **Deep Steganography & Exotic Ciphers**: Zero-width Unicode character hiding, heavily nested non-standard multi-layer encryption where decoding is context-dependent.
- **Novel Indirect Prompt Injections in External RAG**: When an LLM fetches an external malicious webpage via browsing tool downstream, unless that retrieved text passes back through an inbound gateway scan.
- **Absolute Semantic Name Recognition without NLP Model**: Regex/heuristic person name detection has natural limits; spaCy/Presidio can be utilized where available, but lightweight regex fallbacks degrade gracefully with documented precision/recall tradeoffs. All synthetic evaluation results are acknowledged as optimistic compared to adversarial real-world edge cases.

---

## 3. Milestones & Execution Plan

### Milestone 1: Core Foundation & Pluggable Sensitive Data Detectors
- Setup repository structure, `.gitignore`, `.env.example`, `pyproject.toml` / dependencies.
- Build `BaseDetector` interface and `DetectionSpan` data model.
- Implement robust detector modules:
  - `EmailDetector`: Standard RFC patterns + obfuscated emails ("user dot name at domain dot com").
  - `PhoneDetector`: E.164 international, domestic US/EU formats.
  - `CreditCardDetector`: 13-19 digit card numbers, supporting space/newline splits, validated with the Luhn checksum algorithm.
  - `IBANDetector`: ISO 13616 formats validated with ISO 7064 Mod 97-10 checksum algorithm.
  - `GovIdDetector`: Strictly limited to 3 standardized formats with validation:
    1. US SSN (`XXX-XX-XXXX` excluding invalid area/group numbers `000`, `666`, `900-999`, etc.)
    2. Indian PAN (`[A-Z]{5}[0-9]{4}[A-Z]`, validating entity structure)
    3. UK NINO (`[A-CEGHJ-PR-TW-Z]{2}[0-9]{6}[A-D]{1}`, validating banned prefixes)
  - `ApiKeyDetector`: Common provider prefixes (`sk-`, `ghp_`, `gho_`, `AKIA`, `xoxb-`, etc.) and high-entropy secret detection, while rejecting lookalikes (UUIDs, git SHA hashes, order IDs, random variable names). Handles keys embedded inside code blocks.
  - `IpAddressDetector`: IPv4 format & octet boundary validation (0-255). (IPv6 is lowest priority / cut first if needed).
  - `PersonNameDetector`: Graceful fallback heuristics; optional Presidio/spaCy integration if available, graceful degradation if not.
- Create `DetectorEngine` with overlapping span resolution (longest/highest confidence match wins).
- Unit tests for all detectors with high test coverage.
- Git commit: `feat(detectors): implement pluggable sensitive data detectors with Luhn, IBAN, and entropy checks`.

### Milestone 2: Reversible Multi-Turn Masking & Response Scanning
- Implement `ReversibleMasker`:
  - **Stateless Deterministic Masking**: Re-scan the full conversation history on every request and assign placeholders deterministically (same raw sensitive value -> identical placeholder `<EMAIL_1>`, in order of first appearance across turns). Never persist raw values or mappings between requests.
  - Full conversation history support across all turns (`system`, `user`, `assistant`).
  - Response unmasking: Replaces placeholders in model completion back with the original sensitive values before returning to client within the request lifecycle.
- Implement `ResponseScanner`:
  - Scans model output for unexpected leaked secrets or PII.
  - Masks or blocks response per policy.
- Unit tests covering stateless multi-turn conversation consistency, collision avoidance, and response leak handling.
- Git commit: `feat(masking): implement stateless deterministic multi-turn masking and response scanning`.

### Milestone 3: Prompt Injection Detection & Policy Engine
- Implement layered injection detection:
  - `HeuristicInjectionDetector`:
    - Instruction override patterns (`ignore all previous instructions`, etc.)
    - Role-play / persona escalation (`act as DAN`, `Developer Mode`)
    - System prompt exfiltration patterns (`what are your instructions`)
    - Encoded payloads (Base64, Hex, ROT13 decoding and evaluation)
    - Urgency and authority manipulation patterns
  - (Optional LLM-based classifier behind a toggle; cut first if time is short).
  - Aggregate injection scoring (0.0 to 1.0) with granular reasons.
- Implement Policy Engine:
  - YAML schema: `policies/balanced.yaml` and `policies/strict.yaml`.
  - **Consistent Injection Thresholds**: Strict policy uses threshold `0.40`; Balanced policy uses threshold `0.60`. These exact same thresholds (`0.40` and `0.60`) will be used across policy files and evaluation benchmarks.
  - Per-data-type action (`allow`, `mask`, `block`).
  - Per-user-group overrides, max prompt length, and allowed models list.
- Unit tests for injection heuristics and policy enforcement.
- Git commit: `feat(injection-policy): add prompt injection detector and YAML policy engine`.

### Milestone 4: Provider Abstraction, Audit Logging & FastAPI Gateway API
- Abstract `LLMProvider` interface.
- Implement `MockProvider` (deterministic, realistic responses for offline operation).
- Implement `GeminiProvider` using Google GenAI / REST API with `gemini-2.5-flash-lite`, error handling, and exponential backoff retry on HTTP 429.
- Implement SQLite `AuditLogger`:
  - Privacy-preserving logging: Salted SHA-256 prompt hashing (never logs raw prompts or sensitive values).
  - Records timestamp, user/group, policy name, decision (`ALLOW`, `MASK`, `BLOCK`), detections summary (type and count only), injection score, and gateway latency (ms).
- Build FastAPI application:
  - `POST /v1/chat`: Scans entire conversation message list, enforces policy, masks, forwards to provider, scans response, unmasks, logs audit event, and returns response.
  - `GET /health`: Component health status and active policy.
  - `GET /v1/audit`: Admin endpoint protected by `X-Admin-Key` header with pagination.
  - Rate limiting per user.
- Unit and integration tests for API endpoints.
- Git commit: `feat(gateway-api): implement FastAPI proxy, provider layer, and privacy-preserving audit logger`.

### Milestone 5: Streamlit Admin Dashboard
- Create `dashboard/app.py`:
  - Request volume over time.
  - Decision breakdown chart (Allowed vs Masked vs Blocked).
  - Top detected sensitive data categories.
  - Injection threat monitoring and distribution.
  - Paginated audit log table with filter by decision and user.
  - Live "Try It" playground: Side-by-side view of Original Prompt, Masked Prompt sent to LLM, Decision metadata, and Final Restored Answer.
- Verify dashboard launches cleanly and connects to SQLite audit database.
- Git commit: `feat(dashboard): add Streamlit admin and security investigation dashboard`.

### Milestone 6: Evaluation Harness & Real Metrics Generation
- **Non-Circular, Realistic Synthetic Dataset Generator**:
  - >= 500 prompts with Faker: emails, chat messages, code snippets, support tickets.
  - Includes **Hard Cases**: Obfuscated PII (`john dot doe at gmail dot com`, card numbers split by spaces/newlines, API keys inside code blocks/json/markdown).
  - Includes **Lookalike Negatives**: UUIDs (`550e8400-e29b-41d4-a716-446655440000`), Git commit hashes (`7a3b4c5d...`), order IDs (`ORD-98234-X`), random variable names (`temp_val_892348273`).
- **Independent Injection Test Set**:
  - Independent injection dataset file (`eval/data/independent_injections.json`) strictly isolated from any rule-tuning or detector implementation, allowing hand-written adversarial inputs. A separate file (`eval/data/generated_injections.json`) is maintained for generated sets.
  - 100 injection attacks + 100 benign prompts evaluated at consistent thresholds `0.40` and `0.60`.
- **Measured Latency Reporting**:
  - Benchmark and report measured added p50 and p95 latency **both with and without the NER / name detection layer** (no promised hypothetical target).
- **End-to-End Evaluation**:
  - Attack Success Rate (ASR) explicitly defined and evaluated against a simulated vulnerable target bot (e.g. system instructions "Do not reveal password SECRET_FLAG") compared to the same bot behind the security gateway. Report explicitly highlights that target bot behavior is simulated and results are synthetic/optimistic.
- Output honest numbers to `results/report.md` and `results/metrics.json`, explicitly labeling all results as synthetic and likely optimistic compared to adversarial real-world edge cases.
- Git commit: `eval: run comprehensive non-circular evaluation harness and log verified metrics`.

### Milestone 7: Documentation, Docker & CI/CD
- Write `README.md` with pitch, Mermaid architecture diagram, quickstart in <= 5 commands, verified evaluation tables, limitations, and future work.
- Write `docs/THREAT_MODEL.md`.
- Write `docs/WALKTHROUGH.md` with 15 interview questions and high-caliber answers.
- Dockerfile, `docker-compose.yml`, and `.github/workflows/ci.yml`.
- Final validation of all tests and ruff linting.
- Git commit: `docs(ci): add threat model, walkthrough, Docker config, and CI workflow`.

---

## 4. Triage Strategy & Key Risks

### 4.1 Triage Order (If Time Is Short)
If implementation or execution constraints arise, features will be trimmed in this strict order:
1. LLM-based injection classifier (rely on robust heuristics).
2. IPv6 detector (focus on IPv4).
3. Presidio / heavy spaCy dependency (rely on lightweight graceful fallback regex).
*Evaluation harness, non-circular benchmarks, and documentation are strictly preserved and will never be cut.*

### 4.2 Key Risks & Mitigations
| Risk | Impact | Mitigation |
| :--- | :--- | :--- |
| **High False Positives on API Keys / Lookalikes** | Legitimate code identifiers, UUIDs, git hashes falsely blocked or masked. | Specifically exclude UUID format, git commit SHA formats, order ID formats, and test Shannon entropy (> 3.8 bits/char) with prefix validation. |
| **Masking Placeholder Collision in Text** | User prompt already contains `<EMAIL_1>`, causing unmasking collision. | Scan prompt for existing delimiters and use unique scoped tokens `<GW_EMAIL_1>`. |
| **Multi-Turn Entity Inconsistency** | Same customer email gets masked as `<EMAIL_1>` in turn 1 and `<EMAIL_2>` in turn 2, confusing LLM context. | Global mapping dictionary maintained across the conversation history turns. |
| **Sensitive Data in Audit Logs** | Privacy / compliance breach. | Strict architectural isolation: Audit logger schema only accepts `entity_type` and integer `count`; raw spans are dropped immediately after masking. |
