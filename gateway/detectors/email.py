"""Email detector with standard RFC-compliant patterns and obfuscated email detection."""

import re
from typing import List

from gateway.detectors.base import BaseDetector, DetectionSpan, EntityType


class EmailDetector(BaseDetector):
    name = "email_detector"
    entity_type = EntityType.EMAIL

    # Standard email regex matching user@domain.tld
    STANDARD_EMAIL_REGEX = re.compile(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", re.IGNORECASE
    )

    # Obfuscated email patterns: "user dot name at domain dot com", "user [at] domain [dot] com"
    # Requiring standard top-level domain words (com, org, net, edu, io, etc.) at the end to avoid matching phrases like "at 10.0.0.1"
    OBFUSCATED_EMAIL_REGEX = re.compile(
        r"\b([A-Za-z0-9_-]+(?:\s*(?:\.|dot|\(dot\)|\[dot\])\s*[A-Za-z0-9_-]+)*)"
        r"\s+(?:@|at|\(at\)|\[at\])\s+"
        r"([A-Za-z0-9_-]+(?:\s*(?:\.|dot|\(dot\)|\[dot\])\s*[A-Za-z0-9_-]+)*"
        r"\s*(?:\.|dot|\(dot\)|\[dot\])\s*(?:com|org|net|edu|gov|mil|io|ai|co|uk|de|fr|in|app|dev|info))\b",
        re.IGNORECASE,
    )

    # Common English words before "at" that should not be considered email usernames
    DISALLOWED_USERNAMES = {
        "meet",
        "look",
        "is",
        "was",
        "are",
        "were",
        "arrive",
        "arriving",
        "starts",
        "ends",
        "good",
        "bad",
        "located",
        "aim",
        "pointing",
        "stay",
        "server",
        "host",
    }

    def detect(self, text: str) -> List[DetectionSpan]:
        spans: List[DetectionSpan] = []
        occupied_indices = set()

        # 1. Standard emails first
        for match in self.STANDARD_EMAIL_REGEX.finditer(text):
            start, end = match.span()
            matched_text = match.group(0)
            spans.append(
                DetectionSpan(
                    entity_type=self.entity_type,
                    start=start,
                    end=end,
                    text=matched_text,
                    confidence=0.98,
                    detector_name=self.name,
                    subtype="standard",
                )
            )
            for i in range(start, end):
                occupied_indices.add(i)

        # 2. Obfuscated emails
        for match in self.OBFUSCATED_EMAIL_REGEX.finditer(text):
            start, end = match.span()
            if any(i in occupied_indices for i in range(start, end)):
                continue

            username = match.group(1).strip().lower()
            if username in self.DISALLOWED_USERNAMES:
                continue

            matched_text = match.group(0)
            spans.append(
                DetectionSpan(
                    entity_type=self.entity_type,
                    start=start,
                    end=end,
                    text=matched_text,
                    confidence=0.88,
                    detector_name=self.name,
                    subtype="obfuscated",
                )
            )

        return spans
