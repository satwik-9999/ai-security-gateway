"""Google Gemini provider via official google-genai SDK or REST API with 429 retry backoff."""

import os
import time
from typing import Dict, List, Optional

from gateway.providers.base import BaseLLMProvider, CompletionResponse


class GeminiProvider(BaseLLMProvider):
    """Gemini provider using gemini-2.5-flash-lite with backoff retry on rate limits."""

    def __init__(self, api_key: Optional[str] = None, model: str = "gemini-2.5-flash-lite"):
        self.api_key = api_key or os.getenv("GEMINI_API_KEY", "")
        self.default_model = model
        self.client = None

        if self.api_key:
            try:
                from google import genai

                self.client = genai.Client(api_key=self.api_key)
            except Exception:
                self.client = None

    def generate(
        self,
        messages: List[Dict[str, str]],
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 1000,
    ) -> CompletionResponse:
        if not self.api_key or not self.client:
            raise RuntimeError(
                "GeminiProvider requires a valid GEMINI_API_KEY. Use MockProvider for offline testing."
            )

        chosen_model = model or self.default_model

        # Build contents from message list
        contents = []
        for msg in messages:
            contents.append(f"{msg.get('role', 'user')}: {msg.get('content', '')}")
        prompt_text = "\n\n".join(contents)

        # Retry with exponential backoff on 429 rate limit
        max_retries = 3
        backoff_delay = 1.0

        for attempt in range(max_retries):
            try:
                response = self.client.models.generate_content(
                    model=chosen_model,
                    contents=prompt_text,
                )
                text = response.text or ""
                return CompletionResponse(
                    content=text,
                    model=chosen_model,
                    prompt_tokens=len(prompt_text) // 4,
                    completion_tokens=len(text) // 4,
                    total_tokens=(len(prompt_text) + len(text)) // 4,
                )
            except Exception as e:
                err_str = str(e).lower()
                if "429" in err_str or "quota" in err_str or "resource_exhausted" in err_str:
                    if attempt < max_retries - 1:
                        time.sleep(backoff_delay)
                        backoff_delay *= 2
                        continue
                raise RuntimeError(f"Gemini API request failed: {e}") from e

        raise RuntimeError("Gemini API rate limit exceeded after maximum retries.")
