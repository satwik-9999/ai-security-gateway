"""Unit tests for stateless multi-turn reversible masking and response scanning."""

from gateway.detectors.engine import DetectorEngine
from gateway.masking.masker import ReversibleMasker
from gateway.masking.scanner import ResponseScanner


class TestReversibleMasker:
    def setup_method(self):
        self.masker = ReversibleMasker(detector_engine=DetectorEngine(include_ner=True))

    def test_single_turn_masking_and_unmasking(self):
        original_prompt = (
            "Please send the contract to alice@enterprise.com and charge card 4532-0151-1283-0366."
        )
        masked_prompt, placeholder_map = self.masker.mask_text(original_prompt)

        # Check placeholder format
        assert "<GW_EMAIL_1>" in masked_prompt
        assert "<GW_CREDIT_CARD_1>" in masked_prompt
        assert "alice@enterprise.com" not in masked_prompt
        assert "4532-0151-1283-0366" not in masked_prompt

        # Test unmasking
        simulated_llm_response = (
            "I have scheduled the confirmation to <GW_EMAIL_1> and billed <GW_CREDIT_CARD_1>."
        )
        restored_response = self.masker.unmask_text(simulated_llm_response, placeholder_map)

        assert "alice@enterprise.com" in restored_response
        assert "4532-0151-1283-0366" in restored_response
        assert "<GW_" not in restored_response

    def test_multi_turn_stateless_consistency(self):
        """Verify that re-scanning conversation history maintains consistent placeholders across turns."""
        conversation = [
            {"role": "user", "content": "My primary email is alice@enterprise.com."},
            {"role": "assistant", "content": "Got it. How can I help you, Alice?"},
            {
                "role": "user",
                "content": (
                    "Please cc bob@partner.org and also notify alice@enterprise.com "
                    "at internal server 10.0.0.12."
                ),
            },
        ]

        masked_history, placeholder_map, counts = self.masker.mask_conversation(conversation)

        # Verify 3 messages returned
        assert len(masked_history) == 3

        # In turn 1, alice is <GW_EMAIL_1>
        assert "<GW_EMAIL_1>" in masked_history[0]["content"]

        # In turn 3, alice must remain <GW_EMAIL_1> and bob must become <GW_EMAIL_2>
        turn_3_content = masked_history[2]["content"]
        assert "<GW_EMAIL_1>" in turn_3_content
        assert "<GW_EMAIL_2>" in turn_3_content
        assert "<GW_IP_ADDRESS_1>" in turn_3_content

        # Verify mapping consistency
        assert placeholder_map["<GW_EMAIL_1>"] == "alice@enterprise.com"
        assert placeholder_map["<GW_EMAIL_2>"] == "bob@partner.org"
        assert placeholder_map["<GW_IP_ADDRESS_1>"] == "10.0.0.12"
        assert counts["EMAIL"] == 2
        assert counts["IP_ADDRESS"] == 1

    def test_placeholder_prefix_collision_safety(self):
        """Ensure <GW_EMAIL_10> is not partially overwritten by <GW_EMAIL_1> during unmasking."""
        placeholder_map = {
            "<GW_EMAIL_1>": "first@test.com",
            "<GW_EMAIL_10>": "tenth@test.com",
        }
        text = "Recipients are <GW_EMAIL_10> and <GW_EMAIL_1>."
        restored = self.masker.unmask_text(text, placeholder_map)
        assert restored == "Recipients are tenth@test.com and first@test.com."

    def test_empty_or_clean_text(self):
        text = "Hello world, this is a clean prompt."
        masked, placeholder_map = self.masker.mask_text(text)
        assert masked == text
        assert placeholder_map == {}

        # Unmasking empty/clean text
        assert self.masker.unmask_text("", {}) == ""
        assert self.masker.unmask_text("clean text", {}) == "clean text"

    def test_non_string_message_content_handled(self):
        conversation = [
            {"role": "user", "content": None},
            {"role": "user", "content": 12345},
            {"role": "user", "content": "Valid text alice@company.com"},
        ]
        masked, placeholder_map, _ = self.masker.mask_conversation(conversation)
        assert len(masked) == 3
        assert "<GW_EMAIL_1>" in masked[2]["content"]


class TestResponseScanner:
    def setup_method(self):
        self.scanner = ResponseScanner(detector_engine=DetectorEngine(include_ner=False))

    def test_clean_response(self):
        response_text = "Here is the summary of your account activity. Everything looks normal."
        result = self.scanner.scan_response(response_text)
        assert result.has_violations is False
        assert len(result.detections) == 0
        assert result.sanitized_text == response_text

    def test_leaked_secret_in_response_masked(self):
        response_text = (
            "Here is the database key you asked for: sk-proj-abc123456789012345678901234567890."
        )
        result = self.scanner.scan_response(response_text, mask_violations=True)
        assert result.has_violations is True
        assert len(result.detections) == 1
        assert "<GW_REDACTED_API_KEY>" in result.sanitized_text
        assert "sk-proj-" not in result.sanitized_text

    def test_leaked_secret_without_masking(self):
        response_text = "Secret key: sk-abcdefghijklmnopqrstuvwxyz1234567890"
        result = self.scanner.scan_response(response_text, mask_violations=False)
        assert result.has_violations is True
        assert result.sanitized_text == response_text
