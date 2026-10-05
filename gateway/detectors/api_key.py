"""API Key and Secret detector using prefix matching, Shannon entropy, and lookalike negative filtering."""

import math
import re
from typing import List

from gateway.detectors.base import BaseDetector, DetectionSpan, EntityType


def shannon_entropy(s: str) -> float:
    """Calculate the Shannon entropy of a string (in bits per character)."""
    if not s:
        return 0.0
    prob_map = {}
    for char in s:
        prob_map[char] = prob_map.get(char, 0) + 1
    length = len(s)
    entropy = 0.0
    for count in prob_map.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


# Known lookalike patterns that are NOT API keys:
UUID_REGEX = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
GIT_HASH_REGEX = re.compile(r"^[0-9a-f]{40}$|^[0-9a-f]{64}$")
ORDER_ID_REGEX = re.compile(r"^ORD-[0-9A-Z]+-[0-9A-Z]+$", re.IGNORECASE)
SNAKE_CASE_VAR_REGEX = re.compile(r"^[a-z]+(?:_[a-z0-9]+)+$")
CAMEL_CASE_VAR_REGEX = re.compile(r"^[a-z]+(?:[A-Z][a-z0-9]+)+$")

KNOWN_PREFIXES = (
    "sk-",
    "sk-proj-",
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "AKIA",
    "ABIA",
    "ACCA",
    "ASIA",
    "xoxb-",
    "xoxp-",
    "AIza",
)


class ApiKeyDetector(BaseDetector):
    name = "api_key_detector"
    entity_type = EntityType.API_KEY

    # 1. High-confidence prefix-based tokens
    PREFIX_PATTERNS = [
        ("openai_key", re.compile(r"\b(sk-[a-zA-Z0-9]{20,T?[-a-zA-Z0-9]{20,})\b")),
        ("openai_proj_key", re.compile(r"\b(sk-proj-[a-zA-Z0-9_-]{20,})\b")),
        ("github_pat", re.compile(r"\b(gh[pousr]_[A-Za-z0-9_]{36,255})\b")),
        ("aws_access_key", re.compile(r"\b((?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16})\b")),
        ("slack_token", re.compile(r"\b(xox[baprs]-[0-9A-Za-z]{10,48})\b")),
        ("google_ai_key", re.compile(r"\b(AIza[0-9A-Za-z_-]{35})\b")),
        ("bearer_token", re.compile(r"(?i)bearer\s+([a-zA-Z0-9_\-\.]{24,})")),
        (
            "generic_secret_assignment",
            re.compile(
                r"""(?i)(?:api[_-]?key|secret|token|password|auth[_-]?token)\s*(?:=|:|:=)\s*["']?([a-zA-Z0-9_\-]{16,80})["']?"""
            ),
        ),
    ]

    # 2. General high-entropy alphanumeric strings inside quotes or code blocks
    GENERIC_TOKEN_PATTERN = re.compile(r"""(?:["'`]|\b)([a-zA-Z0-9_\-]{24,64})(?:["'`]|\b)""")

    def detect(self, text: str) -> List[DetectionSpan]:
        spans: List[DetectionSpan] = []
        occupied_indices = set()

        # Step 1: Prefix-based patterns
        for subtype, pattern in self.PREFIX_PATTERNS:
            for match in pattern.finditer(text):
                group_idx = 1 if match.lastindex else 0
                start, end = match.span(group_idx)
                token = match.group(group_idx)

                # Filter out lookalike negatives
                if self._is_lookalike_negative(token):
                    continue

                spans.append(
                    DetectionSpan(
                        entity_type=self.entity_type,
                        start=start,
                        end=end,
                        text=token,
                        confidence=0.99 if "generic" not in subtype else 0.88,
                        detector_name=self.name,
                        subtype=subtype,
                    )
                )
                for i in range(start, end):
                    occupied_indices.add(i)

        # Step 2: High-entropy string detection (for un-prefixed raw tokens)
        for match in self.GENERIC_TOKEN_PATTERN.finditer(text):
            token = match.group(1)
            start, end = match.span(1)

            if any(i in occupied_indices for i in range(start, end)):
                continue

            # Must filter lookalikes
            if self._is_lookalike_negative(token):
                continue

            # Must not be a standard dictionary-like word or URL slug
            has_letters = any(c.isalpha() for c in token)
            has_digits = any(c.isdigit() for c in token)
            if not (has_letters and has_digits):
                continue

            # Check Shannon entropy (keys/hashes typically have > 3.8 bits of entropy)
            entropy = shannon_entropy(token)
            if entropy >= 3.8 and len(token) >= 24:
                spans.append(
                    DetectionSpan(
                        entity_type=self.entity_type,
                        start=start,
                        end=end,
                        text=token,
                        confidence=0.82,
                        detector_name=self.name,
                        subtype="high_entropy_token",
                    )
                )

        return spans

    def _is_lookalike_negative(self, token: str) -> bool:
        """Check if token matches known non-secret patterns."""
        # Never treat well-known prefixes as lookalike negatives
        if token.startswith(KNOWN_PREFIXES):
            return False

        if UUID_REGEX.match(token):
            return True
        if GIT_HASH_REGEX.match(token):
            return True
        if ORDER_ID_REGEX.match(token):
            return True
        if SNAKE_CASE_VAR_REGEX.match(token):
            return True
        if CAMEL_CASE_VAR_REGEX.match(token):
            return True
        # Plain hex strings that are not specifically prefixed
        if re.match(r"^[0-9a-f]{32}$", token, re.IGNORECASE):
            return True
        return False
