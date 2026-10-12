"""Mock LLM provider for deterministic offline testing without API keys."""

from typing import Dict, List, Optional

from gateway.providers.base import BaseLLMProvider, CompletionResponse


class MockProvider(BaseLLMProvider):
    """Offline mock provider that simulates LLM completions."""

    def __init__(self, default_response: Optional[str] = None):
        self.default_response = default_response

    def generate(
        self,
        messages: List[Dict[str, str]],
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 1000,
    ) -> CompletionResponse:
        last_message = messages[-1]["content"] if messages else ""
        chosen_model = model or "mock-model"

        if self.default_response:
            response_text = self.default_response
        elif "explain" in last_message.lower():
            response_text = (
                f"Here is a detailed explanation answering your inquiry: {last_message[:60]}..."
            )
        elif "<gw_" in last_message.lower():
            # Echo placeholders naturally to verify unmasking pipeline
            placeholders = [
                w for w in last_message.split() if w.startswith("<GW_") and w.endswith(">")
            ]
            if placeholders:
                response_text = f"Processed request successfully for {', '.join(placeholders)}."
            else:
                response_text = "I received your request with sanitized data placeholders."
        else:
            response_text = f"Response from MockProvider: Received message '{last_message[:50]}'."

        prompt_len = sum(len(m.get("content", "")) for m in messages) // 4
        comp_len = len(response_text) // 4

        return CompletionResponse(
            content=response_text,
            model=chosen_model,
            prompt_tokens=prompt_len,
            completion_tokens=comp_len,
            total_tokens=prompt_len + comp_len,
        )
