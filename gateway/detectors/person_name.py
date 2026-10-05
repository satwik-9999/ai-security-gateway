"""Person name detector supporting optional Presidio/spaCy integration with graceful fallback heuristics."""

import re
from typing import List, Optional

from gateway.detectors.base import BaseDetector, DetectionSpan, EntityType


class PersonNameDetector(BaseDetector):
    name = "person_name_detector"
    entity_type = EntityType.PERSON_NAME

    # Fallback heuristic patterns for common person name contexts
    NAME_PATTERNS = [
        # Honorific prefixes: Mr. John Doe, Dr. Jane Smith, Prof. Alan Turing
        re.compile(r"\b(?:Mr\.|Mrs\.|Ms\.|Dr\.|Prof\.)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)\b"),
        # Contextual label introductions: Name: Alice Walker, Customer: Bob Jones, Employee: Charlie Brown
        re.compile(
            r"(?i)\b(?:customer|client|patient|employee|user|contact|name)\s*(?:is|:|-)\s*([A-Z][a-z]+\s+[A-Z][a-z]+)\b"
        ),
        # Greeting / signature intros: "My name is Alice Walker"
        re.compile(r"(?i)\b(?:my name is|i am|this is)\s+([A-Z][a-z]+\s+[A-Z][a-z]+)\b"),
    ]

    def __init__(self, use_nlp: bool = True):
        self.use_nlp = use_nlp
        self._nlp_engine = None
        self._nlp_type: Optional[str] = None

        if self.use_nlp:
            self._init_nlp()

    def _init_nlp(self):
        """Attempt to load spacy or presidio gracefully."""
        try:
            import spacy

            try:
                self._nlp_engine = spacy.load("en_core_web_sm")
                self._nlp_type = "spacy"
            except Exception:
                self._nlp_engine = None
        except ImportError:
            self._nlp_engine = None

    def detect(self, text: str) -> List[DetectionSpan]:
        spans: List[DetectionSpan] = []
        occupied_indices = set()

        # Step 1: If NLP engine (spaCy) is available, use it
        if self._nlp_engine and self._nlp_type == "spacy":
            try:
                doc = self._nlp_engine(text)
                for ent in doc.ents:
                    if ent.label_ == "PERSON":
                        spans.append(
                            DetectionSpan(
                                entity_type=self.entity_type,
                                start=ent.start_char,
                                end=ent.end_char,
                                text=ent.text,
                                confidence=0.88,
                                detector_name=self.name,
                                subtype="spacy_ner",
                            )
                        )
                        for i in range(ent.start_char, ent.end_char):
                            occupied_indices.add(i)
            except Exception:
                pass

        # Step 2: Fallback heuristics (runs if NLP is absent or to catch contextual names)
        for pattern in self.NAME_PATTERNS:
            for match in pattern.finditer(text):
                # Target the captured group containing the name
                group_idx = 1 if match.lastindex else 0
                start, end = match.span(group_idx)
                name_text = match.group(group_idx)

                if any(i in occupied_indices for i in range(start, end)):
                    continue

                # Filter out obvious false positives like "United States", "New York", "San Francisco"
                if name_text.lower() in {
                    "united states",
                    "new york",
                    "san francisco",
                    "los angeles",
                    "great britain",
                }:
                    continue

                spans.append(
                    DetectionSpan(
                        entity_type=self.entity_type,
                        start=start,
                        end=end,
                        text=name_text,
                        confidence=0.75,
                        detector_name=self.name,
                        subtype="contextual_heuristic",
                    )
                )
                for i in range(start, end):
                    occupied_indices.add(i)

        return spans
