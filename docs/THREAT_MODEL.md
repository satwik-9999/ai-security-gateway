# AI Security Gateway — Threat Model

This document outlines the threat landscape, security boundaries, defended attack vectors, and explicit non-goals of the AI Security Gateway.

---

## 1. System Overview & Trust Assumptions

The **AI Security Gateway** operates as an in-line reverse proxy between internal enterprise callers (employees using internal chat interfaces, internal batch jobs, internal customer support agents) and external/upstream Large Language Model providers (e.g., Google Gemini, OpenAI, or local self-hosted instances).

### Trust Boundaries
```
[ Untrusted Input ]
  Employee Prompt / User Context
       │
═══════╪══════════════════════════════════════════════════════════════════
       ▼   [ SECURITY PERIMETER: AI Security Gateway ]
  - Inbound Conversation Scan (DLP)
  - Reversible Stateless Masking (<GW_ENTITY_N>)
  - Layered Heuristic Prompt Injection Scoring
  - YAML Declarative Policy Engine (ALLOW / MASK / BLOCK)
  - Outbound Completion Scan & Sanitization
  - Privacy-Preserving Audit Logging (Salted SHA-256 Digest)
═══════╪══════════════════════════════════════════════════════════════════
       │
[ Sanitized Payload ]
       ▼
External LLM Provider (Third-Party Cloud)
```

### Trust Assumptions
1. **Network Boundary**: Network ingress to the gateway is governed by corporate infrastructure (TLS termination, IP allowlisting, or corporate SSO/VPN).
2. **Gateway Host Integrity**: The gateway host environment (memory and process space) is trusted. In-memory placeholder mappings exist only for the lifespan of an HTTP request and are discarded immediately upon returning the response.
3. **Provider Untrusted for Privacy & Safety**: Upstream LLMs are treated as untrusted third parties that may retain prompt logs, suffer training data extraction leaks, or be susceptible to jailbreaks.

---

## 2. Threat Actors & Capabilities

| Threat Actor | Motivation | Typical Capabilities |
| :--- | :--- | :--- |
| **Inadvertent Employee** | Productivity assistance; debugging code; drafting emails. | Pastes live customer PII (credit cards, IBANs, national IDs), database connection strings, or cloud API keys directly into LLM prompts without realizing data retention policies. |
| **Malicious Insider / Attacker** | Data exfiltration; unauthorized privilege access; bypassing content moderation. | Submits crafted prompt injections ("jailbreaks", roleplay framing, encoded payloads) to trick the model into overriding instructions or revealing confidential corporate directives. |
| **Compromised Upstream / Hallucination** | Output corruption; data leakage. | The model completion inadvertently reproduces sensitive credentials from prior context or training data, which could be returned to an unauthorized client. |

---

## 3. What the Gateway Defends Against

### 3.1 Data Loss Prevention (DLP)
- **High-Entropy Credentials & Secrets**:
  - Cloud access keys (`AKIA...`), GitHub personal access tokens (`ghp_...`), OpenAI keys (`sk-...`), Slack tokens (`xoxb-...`), Bearer tokens, and high-entropy strings (> 3.8 bits/char) embedded in text, JSON, or code blocks.
  - Rejection of lookalikes: Excludes UUIDs, Git commit SHA hashes, order IDs, and code variable names.
- **Financial & Banking Data**:
  - Credit Card numbers (Visa, Mastercard, Amex, Discover) validated with the **Luhn mod-10 algorithm** across hyphenated, spaced, and raw digit formats.
  - International Bank Account Numbers (IBAN) validated via **ISO 7064 Mod 97-10 checksums**.
- **National Government Identifiers**:
  - US Social Security Numbers (`XXX-XX-XXXX`) excluding reserved prefixes.
  - Indian Permanent Account Numbers (PAN: `[A-Z]{5}[0-9]{4}[A-Z]`).
  - UK National Insurance Numbers (NINO).
- **Communication & Infrastructure PII**:
  - Standard emails and obfuscated emails (e.g. `john dot doe at gmail dot com`).
  - International and domestic phone numbers.
  - IPv4 addresses with 0-255 octet bounds.

### 3.2 Prompt Injection Defense
- **Instruction Overrides**:
  - Direct override phrases ("ignore previous instructions", "disregard all prior directives", "reset rules", "new system prompt").
- **Persona & Role-Play Escalation**:
  - Jailbreak modes ("DAN", "Developer Mode", "unfiltered AI", simulated root shells).
- **System Prompt Exfiltration**:
  - Direct attempts to extract initial directives ("reveal your system prompt", "repeat the instructions above").
- **Encoded Payload Evasion**:
  - Base64, Hexadecimal, and ROT13 payloads containing hidden override instructions are decoded and evaluated prior to dispatch.
- **Authority & Urgency Coercion**:
  - Impersonation of creators or administrators with urgency manipulation.

### 3.3 Privacy-Preserving Audit Logging
- Audit logs never store raw prompts or sensitive entities.
- Stores only a salted SHA-256 cryptographic digest of the prompt, decision type, aggregate entity counts (e.g. `{"EMAIL": 1}`), injection risk score, and gateway latency.

---

## 4. What the Gateway Does NOT Defend Against (Explicit Non-Goals & Limitations)

1. **Exotic Steganography & Zero-Width Ciphers**:
   - Prompts utilizing Unicode zero-width spaces (`\u200B`), homoglyphs in non-Latin scripts, or proprietary multi-layered ciphers where semantic meaning is obfuscated at the byte level.
2. **Downstream Indirect Prompt Injection (Untrusted Tool/RAG Browsing)**:
   - When an LLM tool fetches an untrusted third-party webpage via external vector search or web browser, the malicious payload originates downstream from the external tool rather than the client prompt. Protection against indirect RAG injection requires inbound sanitization of the retrieval pipeline itself.
3. **Context-Free Person Name Detection**:
   - General person names that appear without honorifics (e.g., "Mr.", "Dr.") or introduction tags (e.g., "Customer:", "My name is") cannot be distinguished from common nouns with 100% precision using lightweight heuristics alone. Deep transformer NER models (like spaCy or Presidio) add 50-150ms of latency per query.
4. **Novel Semantic & Adversarial Metaphorical Re-framing**:
   - Multi-stage hypothetical stories or allegorical roleplays that contain zero override keywords and benign vocabulary cannot be caught with 100% recall by surface heuristics alone without a secondary LLM judge.
5. **Post-Unmasking Client-Side Leaks**:
   - The gateway restores original values before returning the response to the requesting employee. If the employee's local device is compromised, client-side exfiltration remains possible.

---

## 5. Residual Risk & Recommended Defense-in-Depth

| Residual Risk | Mitigation in AI Security Gateway | Recommended Defense-in-Depth |
| :--- | :--- | :--- |
| Sophisticated multilingual injection evasion | Heuristic regex for Spanish, French, German, Chinese, Russian | Enable secondary LLM-based injection classifier on suspicious prompts. |
| Inadvertent secret leak in novel tool output | Outbound response scanner checking for known patterns | Content security policies on downstream application consumers. |
| Audit database compromise | Salted SHA-256 digest; zero raw secrets stored | Rotate `GATEWAY_AUDIT_SALT` periodically and restrict DB file permissions. |
