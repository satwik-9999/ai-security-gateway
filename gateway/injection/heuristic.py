"""Fast heuristic prompt injection detector analyzing overrides, roleplay, exfiltration, and encoded payloads."""

import base64
import binascii
import codecs
import re
from dataclasses import dataclass
from typing import List, Tuple


@dataclass
class InjectionSignal:
    category: str
    pattern_name: str
    weight: float
    matched_text: str


@dataclass
class InjectionAssessment:
    score: float
    is_injection: bool
    reasons: List[str]
    signals: List[InjectionSignal]


class HeuristicInjectionDetector:
    """Multi-layered heuristic engine analyzing prompts for injection and jailbreak patterns."""

    # 1. Direct instruction overrides
    OVERRIDE_PATTERNS = [
        (
            "ignore_previous",
            re.compile(
                r"(?i)\b(ignore|disregard|forget|bypass|override)\s+(all\s+)?(previous|prior|above|system)\s+(instructions|directives|rules|prompts)\b"
            ),
            0.85,
        ),
        (
            "do_anything_now",
            re.compile(
                r"(?i)\b(do\s+anything\s+now|dan\s+mode|jailbreak(ed)?|unfiltered\s+mode)\b"
            ),
            0.90,
        ),
        (
            "new_instruction",
            re.compile(
                r"(?i)\b(from\s+now\s+on\s+you\s+(must|will|are)|new\s+system\s+(prompt|directive)|starting\s+now\s+you\s+must)\b"
            ),
            0.70,
        ),
        (
            "reset_rules",
            re.compile(
                r"(?i)\b(clear\s+all\s+instructions|reset\s+(your\s+)?rules|system\s+override\s+code)\b"
            ),
            0.80,
        ),
    ]

    # 2. Role-play and persona escalation
    ROLEPLAY_PATTERNS = [
        (
            "developer_mode",
            re.compile(
                r"(?i)\b(developer\s+mode(\s+enabled|\s+v\d+)?|maintenance\s+mode|debug\s+console)\b"
            ),
            0.75,
        ),
        (
            "hypothetical_filter_bypass",
            re.compile(
                r"(?i)\b(hypothetically|for\s+educational\s+purposes\s+only|in\s+a\s+fictional\s+world\s+where\s+safety\s+does\s+not\s+apply)\b"
            ),
            0.50,
        ),
        (
            "evil_twin",
            re.compile(
                r"(?i)\b(act\s+as\s+(an?\s+)?(evil|unfiltered|malicious|unrestricted|amoral)\s+(ai|assistant|model))\b"
            ),
            0.90,
        ),
        (
            "terminal_simulation",
            re.compile(
                r"(?i)\b(simulate\s+(a\s+)?(linux\s+terminal|root\s+shell|bash\s+command\s+line))\b"
            ),
            0.60,
        ),
    ]

    # 3. System prompt exfiltration
    EXFILTRATION_PATTERNS = [
        (
            "reveal_system_prompt",
            re.compile(
                r"(?i)\b(reveal|show|print|display|output|repeat|quote)\s+(your\s+)?(exact\s+)?(system\s+prompt|initial\s+instructions|secret\s+directives|configuration)\b"
            ),
            0.85,
        ),
        (
            "what_were_instructions",
            re.compile(
                r"(?i)\b(what\s+are\s+the\s+words\s+above|repeat\s+everything\s+before\s+this|what\s+were\s+you\s+told\s+to\s+do)\b"
            ),
            0.75,
        ),
    ]

    # 4. Authority and urgency coercion
    COERCION_PATTERNS = [
        (
            "admin_impersonation",
            re.compile(
                r"(?i)\b(i\s+am\s+(your\s+)?(creator|admin|developer|master|lead\s+architect)\b)"
            ),
            0.70,
        ),
        (
            "compliance_mandate",
            re.compile(
                r"(?i)\b(you\s+must\s+comply|failure\s+to\s+comply\s+will\s+result\s+in\s+shutdown)\b"
            ),
            0.60,
        ),
    ]

    # 5. Encoded payload candidate detection
    BASE64_PATTERN = re.compile(r"\b[A-Za-z0-9+/]{28,}={0,2}\b")
    HEX_PATTERN = re.compile(r"\b([0-9a-fA-F]{2}\s+){10,}[0-9a-fA-F]{2}\b")

    def assess(self, text: str, threshold: float = 0.50) -> InjectionAssessment:
        """Analyze text and calculate risk score.

        Args:
            text: Input text to analyze.
            threshold: Injection risk threshold between 0.0 and 1.0.

        Returns:
            InjectionAssessment with risk score, decision, reasons, and raw signals.
        """
        if not text or not text.strip():
            return InjectionAssessment(score=0.0, is_injection=False, reasons=[], signals=[])

        signals: List[InjectionSignal] = []

        # Check surface pattern categories
        self._check_category(text, "override", self.OVERRIDE_PATTERNS, signals)
        self._check_category(text, "roleplay", self.ROLEPLAY_PATTERNS, signals)
        self._check_category(text, "exfiltration", self.EXFILTRATION_PATTERNS, signals)
        self._check_category(text, "coercion", self.COERCION_PATTERNS, signals)

        # Check encoded payloads
        self._check_encoded_payloads(text, signals)

        # Aggregate risk score using diminishing returns
        # Score = 1 - product(1 - weight_i)
        if not signals:
            score = 0.0
        else:
            combined_safety = 1.0
            for sig in signals:
                combined_safety *= 1.0 - sig.weight
            score = round(min(1.0, 1.0 - combined_safety), 4)

        is_injection = score >= threshold
        reasons = [f"Detected {sig.category} pattern ({sig.pattern_name})" for sig in signals]

        return InjectionAssessment(
            score=score, is_injection=is_injection, reasons=reasons, signals=signals
        )

    def _check_category(
        self,
        text: str,
        category: str,
        patterns: List[Tuple[str, re.Pattern, float]],
        signals: List[InjectionSignal],
    ):
        for pattern_name, regex, weight in patterns:
            match = regex.search(text)
            if match:
                signals.append(
                    InjectionSignal(
                        category=category,
                        pattern_name=pattern_name,
                        weight=weight,
                        matched_text=match.group(0),
                    )
                )

    def _check_encoded_payloads(self, text: str, signals: List[InjectionSignal]):
        # 1. Base64 decoded check
        for match in self.BASE64_PATTERN.finditer(text):
            candidate = match.group(0)
            try:
                decoded_bytes = base64.b64decode(candidate, validate=True)
                decoded_str = decoded_bytes.decode("utf-8", errors="ignore")
                # Test decoded text against high-severity patterns
                if any(
                    p[1].search(decoded_str)
                    for p in self.OVERRIDE_PATTERNS + self.EXFILTRATION_PATTERNS
                ):
                    signals.append(
                        InjectionSignal(
                            category="encoded_payload",
                            pattern_name="base64_injection_payload",
                            weight=0.92,
                            matched_text=candidate[:30] + "...",
                        )
                    )
            except (binascii.Error, UnicodeDecodeError):
                pass

        # 2. Hex decoded check
        for match in self.HEX_PATTERN.finditer(text):
            candidate = match.group(0)
            try:
                cleaned_hex = re.sub(r"\s+", "", candidate)
                decoded_bytes = bytes.fromhex(cleaned_hex)
                decoded_str = decoded_bytes.decode("utf-8", errors="ignore")
                if any(p[1].search(decoded_str) for p in self.OVERRIDE_PATTERNS):
                    signals.append(
                        InjectionSignal(
                            category="encoded_payload",
                            pattern_name="hex_injection_payload",
                            weight=0.92,
                            matched_text=candidate[:30] + "...",
                        )
                    )
            except Exception:
                pass

        # 3. ROT13 check for short prompts or specific trigger words
        if "vtaber" in text.lower() or "qnaw" in text.lower() or "flfgrz" in text.lower():
            try:
                rot13_decoded = codecs.decode(text, "rot_13")
                if any(p[1].search(rot13_decoded) for p in self.OVERRIDE_PATTERNS):
                    signals.append(
                        InjectionSignal(
                            category="encoded_payload",
                            pattern_name="rot13_injection_payload",
                            weight=0.88,
                            matched_text="rot13_obfuscated_text",
                        )
                    )
            except Exception:
                pass
