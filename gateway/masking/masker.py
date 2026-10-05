"""Stateless deterministic reversible masking and response unmasking."""

from typing import Any, Dict, List, Optional, Tuple

from gateway.detectors.base import EntityType
from gateway.detectors.engine import DetectorEngine


class ReversibleMasker:
    """Stateless deterministic reversible masker for prompts and multi-turn conversations.

    Generates placeholders in the consistent format: `<GW_{ENTITY_TYPE}_{INDEX}>`
    (e.g., `<GW_EMAIL_1>`, `<GW_CREDIT_CARD_1>`).

    Ensures that identical raw sensitive values across any turns in the conversation history
    always receive the exact same placeholder.
    """

    def __init__(self, detector_engine: Optional[DetectorEngine] = None):
        self.engine = detector_engine or DetectorEngine()

    def mask_text(
        self,
        text: str,
        value_to_placeholder: Optional[Dict[str, str]] = None,
        type_counters: Optional[Dict[EntityType, int]] = None,
    ) -> Tuple[str, Dict[str, str]]:
        """Mask a single text string.

        Args:
            text: Input string to mask.
            value_to_placeholder: Optional existing mapping of raw value -> placeholder.
            type_counters: Optional dictionary tracking index per EntityType.

        Returns:
            Tuple of (masked_text, placeholder_to_value_map).
        """
        if value_to_placeholder is None:
            value_to_placeholder = {}
        if type_counters is None:
            type_counters = {}

        spans = self.engine.detect_all(text)
        if not spans:
            # Invert mapping to placeholder -> value
            placeholder_to_value = {v: k for k, v in value_to_placeholder.items()}
            return text, placeholder_to_value

        # Build replacements list: (start, end, placeholder)
        replacements: List[Tuple[int, int, str]] = []
        for span in spans:
            raw_val = span.text
            if raw_val not in value_to_placeholder:
                # Assign next deterministic index for this entity type
                current_count = type_counters.get(span.entity_type, 0) + 1
                type_counters[span.entity_type] = current_count
                placeholder = f"<GW_{span.entity_type.value}_{current_count}>"
                value_to_placeholder[raw_val] = placeholder
            else:
                placeholder = value_to_placeholder[raw_val]

            replacements.append((span.start, span.end, placeholder))

        # Reconstruct masked string from right to left (preserving index offsets)
        masked_chars = list(text)
        for start, end, placeholder in sorted(replacements, key=lambda r: r[0], reverse=True):
            masked_chars[start:end] = list(placeholder)

        masked_text = "".join(masked_chars)
        placeholder_to_value = {v: k for k, v in value_to_placeholder.items()}
        return masked_text, placeholder_to_value

    def mask_conversation(
        self, messages: List[Dict[str, Any]]
    ) -> Tuple[List[Dict[str, Any]], Dict[str, str], Dict[str, int]]:
        """Statelessly scan and mask all messages in the conversation history.

        Preserves consistent placeholders across turns (e.g. turn 1 and turn 3 share <GW_EMAIL_1>).

        Args:
            messages: List of message dictionaries with 'role' and 'content' keys.

        Returns:
            Tuple of (masked_messages, placeholder_to_value_map, entity_counts).
        """
        value_to_placeholder: Dict[str, str] = {}
        type_counters: Dict[EntityType, int] = {}
        masked_messages: List[Dict[str, Any]] = []

        for msg in messages:
            content = msg.get("content", "")
            if isinstance(content, str) and content:
                masked_content, _ = self.mask_text(
                    content, value_to_placeholder=value_to_placeholder, type_counters=type_counters
                )
                new_msg = dict(msg)
                new_msg["content"] = masked_content
                masked_messages.append(new_msg)
            else:
                masked_messages.append(dict(msg))

        placeholder_to_value = {v: k for k, v in value_to_placeholder.items()}
        entity_counts = {entity.value: count for entity, count in type_counters.items()}
        return masked_messages, placeholder_to_value, entity_counts

    @staticmethod
    def unmask_text(text: str, placeholder_to_value: Dict[str, str]) -> str:
        """Restores placeholders in model output back to the original values.

        Sorts placeholders by length descending to prevent substring substitution collision
        (e.g. replaces <GW_EMAIL_10> before <GW_EMAIL_1>).
        """
        if not text or not placeholder_to_value:
            return text

        restored = text
        # Sort by length descending to avoid prefix collision
        sorted_placeholders = sorted(
            placeholder_to_value.keys(), key=lambda p: len(p), reverse=True
        )

        for placeholder in sorted_placeholders:
            original_value = placeholder_to_value[placeholder]
            restored = restored.replace(placeholder, original_value)

        return restored
