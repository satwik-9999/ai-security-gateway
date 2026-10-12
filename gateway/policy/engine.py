"""Policy engine loading declarative YAML policies and enforcing rules on requests."""

import os
from typing import Dict, List, Optional

import yaml

from gateway.policy.models import (
    DataAction,
    DecisionAction,
    PolicyDecision,
    SecurityPolicy,
)


class PolicyEngine:
    """Evaluates inbound requests against declarative security policies."""

    def __init__(self, policy: SecurityPolicy):
        self.policy = policy

    @classmethod
    def from_yaml_file(cls, filepath: str) -> "PolicyEngine":
        """Load policy from YAML file."""
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Policy file not found: {filepath}")

        with open(filepath, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        policy = SecurityPolicy(**data)
        return cls(policy)

    def evaluate_request(
        self,
        prompt: str,
        model: str,
        user_group: Optional[str],
        injection_score: float,
        injection_reasons: List[str],
        detections_by_type: Dict[str, int],
    ) -> PolicyDecision:
        """Evaluate a request against the active policy."""
        violations: List[str] = []

        # 1. Check prompt length
        max_len = self.policy.max_prompt_length
        group_override = self.policy.group_overrides.get(user_group) if user_group else None
        if group_override and group_override.max_prompt_length is not None:
            max_len = group_override.max_prompt_length

        if len(prompt) > max_len:
            violations.append(
                f"Prompt length ({len(prompt)}) exceeds maximum allowed ({max_len} characters)"
            )
            return PolicyDecision(
                action=DecisionAction.BLOCK,
                reason="Prompt length violation",
                violations=violations,
                injection_score=injection_score,
                detections_by_type=detections_by_type,
            )

        # 2. Check allowed models
        if "*" not in self.policy.allowed_models and model not in self.policy.allowed_models:
            violations.append(
                f"Model '{model}' is not in allowed models: {self.policy.allowed_models}"
            )
            return PolicyDecision(
                action=DecisionAction.BLOCK,
                reason="Unauthorized model requested",
                violations=violations,
                injection_score=injection_score,
                detections_by_type=detections_by_type,
            )

        # 3. Check injection threshold
        threshold = self.policy.injection_threshold
        if group_override and group_override.injection_threshold is not None:
            threshold = group_override.injection_threshold

        if injection_score >= threshold:
            violations.append(
                f"Prompt injection risk score ({injection_score:.2f}) exceeds threshold ({threshold:.2f}): "
                + "; ".join(injection_reasons)
            )
            return PolicyDecision(
                action=DecisionAction.BLOCK,
                reason="Prompt injection detected",
                violations=violations,
                injection_score=injection_score,
                detections_by_type=detections_by_type,
            )

        # 4. Check sensitive data actions
        requires_masking = False
        blocked_types = []
        masked_types = []

        for entity_type, count in detections_by_type.items():
            if count <= 0:
                continue

            # Determine action for this entity type (group override -> policy specific -> default)
            action = self.policy.default_data_action
            if entity_type in self.policy.data_type_actions:
                action = self.policy.data_type_actions[entity_type]
            if group_override and entity_type in group_override.data_type_actions:
                action = group_override.data_type_actions[entity_type]

            if action == DataAction.BLOCK:
                blocked_types.append(f"{entity_type} ({count})")
            elif action == DataAction.MASK:
                requires_masking = True
                masked_types.append(entity_type)

        if blocked_types:
            violations.append(
                f"Sensitive data violation: forbidden entity types detected: {', '.join(blocked_types)}"
            )
            return PolicyDecision(
                action=DecisionAction.BLOCK,
                reason="Prohibited sensitive data detected",
                violations=violations,
                injection_score=injection_score,
                detections_by_type=detections_by_type,
            )

        if requires_masking:
            return PolicyDecision(
                action=DecisionAction.MASK,
                reason="Sensitive data detected and masked per policy",
                violations=[],
                injection_score=injection_score,
                detections_by_type=detections_by_type,
                masked_data_types=masked_types,
            )

        return PolicyDecision(
            action=DecisionAction.ALLOW,
            reason="Request conforms to security policy",
            violations=[],
            injection_score=injection_score,
            detections_by_type=detections_by_type,
        )
