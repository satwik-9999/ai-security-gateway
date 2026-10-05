"""Government ID detector for 3 specific standardized formats: US SSN, Indian PAN, UK NINO."""

import re
from typing import List

from gateway.detectors.base import BaseDetector, DetectionSpan, EntityType


class GovIdDetector(BaseDetector):
    name = "gov_id_detector"
    entity_type = EntityType.GOV_ID

    # 1. US SSN: 3 digits - 2 digits - 4 digits (excluding invalid prefixes 000, 666, 900-999)
    US_SSN_PATTERN = re.compile(r"\b(?!000|666|9\d{2})(\d{3})-(?!00)(\d{2})-(?!0000)(\d{4})\b")

    # 2. Indian PAN: 5 uppercase letters, 4 digits, 1 uppercase letter
    IN_PAN_PATTERN = re.compile(r"\b([A-Z]{5}\d{4}[A-Z])\b")

    # 3. UK National Insurance Number (NINO): 2 letters, 6 digits, 1 letter (A-D)
    UK_NINO_PATTERN = re.compile(
        r"\b([A-Z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]{1})\b", re.IGNORECASE
    )

    # Banned first 2 letters for UK NINO
    BANNED_UK_PREFIXES = {"GB", "BG", "NK", "KN", "TN", "NT", "ZZ"}

    def detect(self, text: str) -> List[DetectionSpan]:
        spans: List[DetectionSpan] = []

        # US SSN
        for match in self.US_SSN_PATTERN.finditer(text):
            spans.append(
                DetectionSpan(
                    entity_type=self.entity_type,
                    start=match.start(),
                    end=match.end(),
                    text=match.group(0),
                    confidence=0.98,
                    detector_name=self.name,
                    subtype="us_ssn",
                )
            )

        # Indian PAN
        for match in self.IN_PAN_PATTERN.finditer(text):
            token = match.group(0)
            # 4th letter standard entity types: P, C, H, F, A, T, B, L, J, G
            confidence = 0.98 if token[3] in "PCHFATBLJG" else 0.90
            spans.append(
                DetectionSpan(
                    entity_type=self.entity_type,
                    start=match.start(),
                    end=match.end(),
                    text=token,
                    confidence=confidence,
                    detector_name=self.name,
                    subtype="in_pan",
                )
            )

        # UK NINO
        for match in self.UK_NINO_PATTERN.finditer(text):
            candidate = match.group(0).upper().replace(" ", "")
            prefix = candidate[:2]
            if prefix not in self.BANNED_UK_PREFIXES:
                spans.append(
                    DetectionSpan(
                        entity_type=self.entity_type,
                        start=match.start(),
                        end=match.end(),
                        text=match.group(0),
                        confidence=0.96,
                        detector_name=self.name,
                        subtype="uk_nino",
                    )
                )

        return spans
