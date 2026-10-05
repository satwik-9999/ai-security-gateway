"""Credit card detector with regex extraction and Luhn algorithm checksum validation."""

import re
from typing import List

from gateway.detectors.base import BaseDetector, DetectionSpan, EntityType


def luhn_checksum(card_number_str: str) -> bool:
    """Validate a card number using the Luhn (mod 10) algorithm."""
    digits = [int(c) for c in card_number_str if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False

    checksum = 0
    reverse_digits = digits[::-1]
    for i, digit in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = digit * 2
            checksum += doubled - 9 if doubled > 9 else doubled
        else:
            checksum += digit
    return checksum % 10 == 0


class CreditCardDetector(BaseDetector):
    name = "credit_card_detector"
    entity_type = EntityType.CREDIT_CARD

    # Standard formats: 4 groups of 4 digits, 4-6-5 (Amex), or 13-19 consecutive digits
    # Allowing spaces, dashes, or newlines between digit blocks
    CC_PATTERN = re.compile(
        r"(?:\b|\b(?=[0-9]))"
        r"(?:\d[ -]?){12,18}\d"
        r"(?:\b|(?<=[0-9]))"
    )

    def detect(self, text: str) -> List[DetectionSpan]:
        spans: List[DetectionSpan] = []
        for match in self.CC_PATTERN.finditer(text):
            matched_text = match.group(0)
            raw_digits = re.sub(r"\D", "", matched_text)

            # Check length constraint
            if not (13 <= len(raw_digits) <= 19):
                continue

            # Filter obvious false positives like all repeating digits "0000000000000000"
            if len(set(raw_digits)) == 1:
                continue

            # Run Luhn checksum
            if luhn_checksum(raw_digits):
                # Identify card brand if possible
                subtype = "unknown"
                if raw_digits.startswith("4"):
                    subtype = "visa"
                elif 51 <= int(raw_digits[:2]) <= 55 or 2221 <= int(raw_digits[:4]) <= 2720:
                    subtype = "mastercard"
                elif raw_digits.startswith(("34", "37")):
                    subtype = "amex"
                elif raw_digits.startswith("6011") or raw_digits.startswith("65"):
                    subtype = "discover"

                spans.append(
                    DetectionSpan(
                        entity_type=self.entity_type,
                        start=match.start(),
                        end=match.end(),
                        text=matched_text,
                        confidence=0.99,
                        detector_name=self.name,
                        subtype=subtype,
                    )
                )
        return spans
