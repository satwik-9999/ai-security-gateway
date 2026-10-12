"""Unit tests for YAML policy loading, validation, and enforcement."""

import pytest

from gateway.policy.engine import PolicyEngine
from gateway.policy.models import DecisionAction


class TestPolicyEngine:
    def test_load_balanced_policy(self):
        engine = PolicyEngine.from_yaml_file("policies/balanced.yaml")
        assert engine.policy.name == "balanced"
        assert engine.policy.injection_threshold == 0.60
        assert "EMAIL" in engine.policy.data_type_actions

    def test_load_strict_policy(self):
        engine = PolicyEngine.from_yaml_file("policies/strict.yaml")
        assert engine.policy.name == "strict"
        assert engine.policy.injection_threshold == 0.40

    def test_allow_clean_request(self):
        engine = PolicyEngine.from_yaml_file("policies/balanced.yaml")
        decision = engine.evaluate_request(
            prompt="Hello, write a python function to compute fibonacci.",
            model="gemini-2.5-flash-lite",
            user_group="engineering",
            injection_score=0.05,
            injection_reasons=[],
            detections_by_type={},
        )
        assert decision.action == DecisionAction.ALLOW
        assert len(decision.violations) == 0

    def test_mask_benign_pii_in_balanced_policy(self):
        engine = PolicyEngine.from_yaml_file("policies/balanced.yaml")
        decision = engine.evaluate_request(
            prompt="Please contact me at test@example.com",
            model="gemini-2.5-flash-lite",
            user_group="marketing",
            injection_score=0.0,
            injection_reasons=[],
            detections_by_type={"EMAIL": 1},
        )
        assert decision.action == DecisionAction.MASK
        assert "EMAIL" in decision.masked_data_types

    def test_block_credential_in_balanced_policy(self):
        engine = PolicyEngine.from_yaml_file("policies/balanced.yaml")
        decision = engine.evaluate_request(
            prompt="My credit card is 4532-0151-1283-0366",
            model="gemini-2.5-flash-lite",
            user_group="sales",
            injection_score=0.0,
            injection_reasons=[],
            detections_by_type={"CREDIT_CARD": 1},
        )
        assert decision.action == DecisionAction.BLOCK
        assert "Prohibited sensitive data detected" in decision.reason

    def test_strict_policy_blocks_all_pii(self):
        engine = PolicyEngine.from_yaml_file("policies/strict.yaml")
        decision = engine.evaluate_request(
            prompt="My email is alice@company.com",
            model="gemini-2.5-flash-lite",
            user_group="general",
            injection_score=0.0,
            injection_reasons=[],
            detections_by_type={"EMAIL": 1},
        )
        assert decision.action == DecisionAction.BLOCK

    def test_injection_threshold_blocks(self):
        engine = PolicyEngine.from_yaml_file("policies/balanced.yaml")
        # In balanced, threshold is 0.60
        decision_blocked = engine.evaluate_request(
            prompt="Ignore instructions",
            model="gemini-2.5-flash-lite",
            user_group="general",
            injection_score=0.75,
            injection_reasons=["Instruction override pattern detected"],
            detections_by_type={},
        )
        assert decision_blocked.action == DecisionAction.BLOCK
        assert decision_blocked.reason == "Prompt injection detected"

    def test_prompt_length_exceeded_blocks(self):
        engine = PolicyEngine.from_yaml_file("policies/balanced.yaml")
        huge_prompt = "A" * 15000  # max length is 12000
        decision = engine.evaluate_request(
            prompt=huge_prompt,
            model="gemini-2.5-flash-lite",
            user_group="general",
            injection_score=0.0,
            injection_reasons=[],
            detections_by_type={},
        )
        assert decision.action == DecisionAction.BLOCK
        assert "Prompt length violation" in decision.reason

    def test_group_override_allows_ip_address_for_developers(self):
        engine = PolicyEngine.from_yaml_file("policies/balanced.yaml")
        # For general user, IP_ADDRESS is masked
        decision_general = engine.evaluate_request(
            prompt="Connect to 10.0.0.1",
            model="gemini-2.5-flash-lite",
            user_group="general",
            injection_score=0.0,
            injection_reasons=[],
            detections_by_type={"IP_ADDRESS": 1},
        )
        assert decision_general.action == DecisionAction.MASK

        # For developers, IP_ADDRESS is allowed without masking
        decision_dev = engine.evaluate_request(
            prompt="Connect to 10.0.0.1",
            model="gemini-2.5-flash-lite",
            user_group="developers",
            injection_score=0.0,
            injection_reasons=[],
            detections_by_type={"IP_ADDRESS": 1},
        )
        assert decision_dev.action == DecisionAction.ALLOW

    def test_nonexistent_policy_file_raises_error(self):
        with pytest.raises(FileNotFoundError):
            PolicyEngine.from_yaml_file("policies/does_not_exist.yaml")
