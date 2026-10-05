"""Base classes and data models for sensitive data detectors."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import List, Optional


class EntityType(str, Enum):
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    CREDIT_CARD = "CREDIT_CARD"
    IBAN = "IBAN"
    GOV_ID = "GOV_ID"
    API_KEY = "API_KEY"
    IP_ADDRESS = "IP_ADDRESS"
    PERSON_NAME = "PERSON_NAME"


@dataclass(frozen=True)
class DetectionSpan:
    """Represents a detected sensitive data span within a text string."""

    entity_type: EntityType
    start: int
    end: int
    text: str
    confidence: float
    detector_name: str
    subtype: Optional[str] = None

    def __post_init__(self):
        if self.start < 0 or self.end < self.start:
            raise ValueError(f"Invalid span bounds: start={self.start}, end={self.end}")
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError(f"Confidence must be between 0.0 and 1.0, got {self.confidence}")

    def overlaps_with(self, other: "DetectionSpan") -> bool:
        """Checks if two spans overlap in character indices."""
        return max(self.start, other.start) < min(self.end, other.end)


class BaseDetector(ABC):
    """Abstract base class for all pluggable sensitive data detectors."""

    @property
    @abstractmethod
    def entity_type(self) -> EntityType:
        """The primary entity type this detector targets."""
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        """The human-readable name of the detector."""
        pass

    @abstractmethod
    def detect(self, text: str) -> List[DetectionSpan]:
        """Detect sensitive data occurrences in text.

        Args:
            text: Input text string to scan.

        Returns:
            List of detected DetectionSpan instances.
        """
        pass
