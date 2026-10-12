"""Pydantic models for declarative security policies and decisions."""

from enum import Enum
from typing import Dict, List, Optional

from pydantic import BaseModel, Field


class DataAction(str, Enum):
    ALLOW = "allow"
    MASK = "mask"
    BLOCK = "block"


class DecisionAction(str, Enum):
    ALLOW = "ALLOW"
    MASK = "MASK"
    BLOCK = "BLOCK"


class UserGroupOverride(BaseModel):
    data_type_actions: Dict[str, DataAction] = Field(default_factory=dict)
    injection_threshold: Optional[float] = None
    max_prompt_length: Optional[int] = None


class SecurityPolicy(BaseModel):
    name: str
    description: str
    injection_threshold: float = 0.50
    max_prompt_length: int = 8000
    allowed_models: List[str] = Field(default_factory=lambda: ["*"])
    default_data_action: DataAction = DataAction.BLOCK
    data_type_actions: Dict[str, DataAction] = Field(default_factory=dict)
    group_overrides: Dict[str, UserGroupOverride] = Field(default_factory=dict)


class PolicyDecision(BaseModel):
    action: DecisionAction
    reason: str
    violations: List[str] = Field(default_factory=list)
    injection_score: float = 0.0
    detections_by_type: Dict[str, int] = Field(default_factory=dict)
    masked_data_types: List[str] = Field(default_factory=list)
