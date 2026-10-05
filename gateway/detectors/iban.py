"""IBAN (International Bank Account Number) detector with ISO 7064 mod 97 validation."""

import re
from typing import List

from gateway.detectors.base import BaseDetector, DetectionSpan, EntityType


def validate_iban(iban: str) -> bool:
    """Validate IBAN according to ISO 13616 and ISO 7064 Mod 97-10."""
    cleaned = re.sub(r"\s+", "", iban).upper()
    if len(cleaned) < 15 or len(cleaned) > 34:
        return False

    # Rearrange: first 4 characters moved to the end
    rearranged = cleaned[4:] + cleaned[:4]

    # Replace letters with two digits: A=10, B=11, ..., Z=35
    numeric_str = ""
    for char in rearranged:
        if char.isdigit():
            numeric_str += char
        elif "A" <= char <= "Z":
            numeric_str += str(ord(char) - ord("A") + 10)
        else:
            return False

    # Modulo 97 must equal 1
    return int(numeric_str) % 97 == 1


class IBANDetector(BaseDetector):
    name = "iban_detector"
    entity_type = EntityType.IBAN

    # Matches 2 country code letters followed by 2 check digits, then up to 30 alphanumeric chars
    # Supports optional space separators every 4 characters
    IBAN_PATTERN = re.compile(
        r"\b([A-Z]{2}\d{2}(?:\s?[A-Z0-9]{4}){2,7}(?:\s?[A-Z0-9]{1,4})?)\b", re.IGNORECASE
    )

    def detect(self, text: str) -> List[DetectionSpan]:
        spans: List[DetectionSpan] = []
        for match in self.IBAN_PATTERN.finditer(text):
            candidate = match.group(0)
            if validate_iban(candidate):
                country = candidate[:2].upper()
                spans.append(
                    DetectionSpan(
                        entity_type=self.entity_type,
                        start=match.start(),
                        end=match.end(),
                        text=candidate,
                        confidence=0.99,
                        detector_name=self.name,
                        subtype=f"iban_{country.lower()}",
                    )
                )
        return spans
