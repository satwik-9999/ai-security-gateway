"""Phone number detector supporting international E.164 and standard domestic formats."""

import re
from typing import List

from gateway.detectors.base import BaseDetector, DetectionSpan, EntityType


class PhoneDetector(BaseDetector):
    name = "phone_detector"
    entity_type = EntityType.PHONE

    # International and domestic phone numbers:
    # 1. International with country code: +1-555-123-4567, +44 20 7946 0958, +91 98765 43210
    INTL_PHONE_PATTERN = re.compile(
        r"(?:\+?\d{1,3})[-.\s]?(?:\(?\d{2,4}\)?[-.\s]?)?\d{3,4}[-.\s]?\d{3,4}\b"
    )

    # 2. US standard formats: (555) 123-4567, 555-123-4567, 555.123.4567
    US_PHONE_PATTERN = re.compile(
        r"\b(?:\+?1[-.\s]?)?(?:\(?([2-9]\d{2})\)?[-.\s]?)([2-9]\d{2})[-.\s]?(\d{4})\b"
    )

    def detect(self, text: str) -> List[DetectionSpan]:
        spans: List[DetectionSpan] = []
        occupied_indices = set()

        # 1. Standard US phone patterns (high confidence)
        for match in self.US_PHONE_PATTERN.finditer(text):
            start, end = match.span()
            matched_text = match.group(0)
            # Ensure not just a sequence of zeros or simple dates like 2024-05-12
            digits_only = re.sub(r"\D", "", matched_text)
            if len(digits_only) in (10, 11) and len(set(digits_only)) > 2:
                spans.append(
                    DetectionSpan(
                        entity_type=self.entity_type,
                        start=start,
                        end=end,
                        text=matched_text,
                        confidence=0.95,
                        detector_name=self.name,
                        subtype="domestic_us",
                    )
                )
                for i in range(start, end):
                    occupied_indices.add(i)

        # 2. International phone pattern
        for match in self.INTL_PHONE_PATTERN.finditer(text):
            start, end = match.span()
            if any(i in occupied_indices for i in range(start, end)):
                continue

            matched_text = match.group(0)
            digits_only = re.sub(r"\D", "", matched_text)
            # Legitimate phone numbers generally have 8 to 15 digits
            if 8 <= len(digits_only) <= 15 and len(set(digits_only)) > 2:
                # Require either starting with '+' or having clear grouping formatting
                if matched_text.strip().startswith("+") or any(
                    sep in matched_text for sep in ["-", "(", ")", " "]
                ):
                    # Discard if it looks like an IP or date
                    if not re.match(r"^\d{4}-\d{2}-\d{2}$", matched_text.strip()):
                        spans.append(
                            DetectionSpan(
                                entity_type=self.entity_type,
                                start=start,
                                end=end,
                                text=matched_text,
                                confidence=0.90,
                                detector_name=self.name,
                                subtype="international",
                            )
                        )

        return spans
