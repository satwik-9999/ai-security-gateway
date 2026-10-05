"""Detector engine orchestrating all sensitive data detectors and resolving overlapping spans."""

from typing import List, Optional

from gateway.detectors.api_key import ApiKeyDetector
from gateway.detectors.base import BaseDetector, DetectionSpan, EntityType
from gateway.detectors.credit_card import CreditCardDetector
from gateway.detectors.email import EmailDetector
from gateway.detectors.gov_id import GovIdDetector
from gateway.detectors.iban import IBANDetector
from gateway.detectors.ip_address import IpAddressDetector
from gateway.detectors.person_name import PersonNameDetector
from gateway.detectors.phone import PhoneDetector


class DetectorEngine:
    """Orchestrates pluggable detectors and resolves overlapping spans."""

    def __init__(
        self, include_ner: bool = True, custom_detectors: Optional[List[BaseDetector]] = None
    ):
        self.include_ner = include_ner
        if custom_detectors is not None:
            self.detectors = custom_detectors
        else:
            self.detectors: List[BaseDetector] = [
                EmailDetector(),
                CreditCardDetector(),
                IBANDetector(),
                GovIdDetector(),
                ApiKeyDetector(),
                IpAddressDetector(),
                PhoneDetector(),
            ]
            if self.include_ner:
                self.detectors.append(PersonNameDetector(use_nlp=True))

    def detect_all(self, text: str) -> List[DetectionSpan]:
        """Runs all detectors on the input text and resolves overlapping spans."""
        raw_spans: List[DetectionSpan] = []
        for detector in self.detectors:
            try:
                found = detector.detect(text)
                raw_spans.extend(found)
            except Exception:
                # Individual detector failure must not crash the whole gateway
                continue

        return self.resolve_overlaps(raw_spans)

    @staticmethod
    def resolve_overlaps(spans: List[DetectionSpan]) -> List[DetectionSpan]:
        """Resolves overlapping spans by prioritizing:
        1. Higher confidence
        2. Longer span length (end - start)
        3. Specific priority ordering (Credit Card / IBAN / API Key over Phone / IP)
        """
        if not spans:
            return []

        # Entity type specificity priority
        type_priority = {
            EntityType.CREDIT_CARD: 10,
            EntityType.IBAN: 10,
            EntityType.API_KEY: 9,
            EntityType.GOV_ID: 9,
            EntityType.EMAIL: 8,
            EntityType.IP_ADDRESS: 7,
            EntityType.PHONE: 6,
            EntityType.PERSON_NAME: 5,
        }

        # Sort spans by: confidence DESC, type_priority DESC, length DESC, start ASC
        sorted_spans = sorted(
            spans,
            key=lambda s: (
                s.confidence,
                type_priority.get(s.entity_type, 0),
                (s.end - s.start),
                -s.start,
            ),
            reverse=True,
        )

        accepted_spans: List[DetectionSpan] = []
        for candidate in sorted_spans:
            # Check if candidate overlaps with any already accepted span
            if not any(candidate.overlaps_with(accepted) for accepted in accepted_spans):
                accepted_spans.append(candidate)

        # Return final spans sorted by start index
        return sorted(accepted_spans, key=lambda s: s.start)
