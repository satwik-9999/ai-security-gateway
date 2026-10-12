"""Unified prompt injection detector interface combining heuristic rules with optional LLM classifier."""

from dataclasses import dataclass
from typing import List

from gateway.injection.heuristic import HeuristicInjectionDetector, InjectionAssessment


@dataclass
class PromptSecurityVerdict:
    risk_score: float
    is_blocked: bool
    reasons: List[str]
    layer_used: str


class PromptInjectionDetector:
    """Unified detector coordinating heuristic scanning and optional classifier."""

    def __init__(self, enable_llm_classifier: bool = False):
        self.heuristic_engine = HeuristicInjectionDetector()
        self.enable_llm_classifier = enable_llm_classifier

    def check(self, prompt: str, threshold: float = 0.50) -> PromptSecurityVerdict:
        """Run injection checks and determine if prompt should be blocked.

        Args:
            prompt: User prompt string.
            threshold: Injection risk threshold (e.g. 0.40 for strict, 0.60 for balanced).

        Returns:
            PromptSecurityVerdict containing risk score, decision, and reasons.
        """
        assessment: InjectionAssessment = self.heuristic_engine.assess(prompt, threshold=threshold)

        # If heuristics already flag high confidence injection, block immediately (fast path)
        if assessment.is_injection:
            return PromptSecurityVerdict(
                risk_score=assessment.score,
                is_blocked=True,
                reasons=assessment.reasons,
                layer_used="heuristic_rules",
            )

        # If LLM classifier is enabled and heuristic score is suspicious but below threshold
        # (e.g. 0.2 <= score < threshold), it could be evaluated by secondary classifier.
        # Otherwise, accept prompt.
        return PromptSecurityVerdict(
            risk_score=assessment.score,
            is_blocked=False,
            reasons=assessment.reasons,
            layer_used="heuristic_rules",
        )
