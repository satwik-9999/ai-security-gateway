"""FastAPI application factory and security gateway routing."""

import time
import uuid
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Query, status

from gateway.api.middleware import RateLimiter, create_admin_verifier
from gateway.api.models import (
    AuditQueryResponse,
    ChatChoice,
    ChatMessage,
    ChatRequest,
    ChatResponse,
    HealthResponse,
)
from gateway.audit.logger import AuditLogger
from gateway.detectors.engine import DetectorEngine
from gateway.injection.detector import PromptInjectionDetector
from gateway.masking.masker import ReversibleMasker
from gateway.masking.scanner import ResponseScanner
from gateway.policy.engine import PolicyEngine
from gateway.policy.models import DecisionAction
from gateway.providers.base import BaseLLMProvider
from gateway.providers.mock import MockProvider


def create_app(
    policy_path: str = "policies/balanced.yaml",
    db_path: str = "gateway.db",
    salt: str = "default_audit_salt",
    admin_key: str = "admin-secret-key-change-me",
    provider: Optional[BaseLLMProvider] = None,
    include_ner: bool = True,
) -> FastAPI:
    """Build and configure the AI Security Gateway FastAPI application."""

    app = FastAPI(
        title="AI Security Gateway",
        description="Enterprise reverse proxy for DLP and Prompt Injection Defense",
        version="0.1.0",
    )

    # Initialize components
    policy_engine = PolicyEngine.from_yaml_file(policy_path)
    detector_engine = DetectorEngine(include_ner=include_ner)
    masker = ReversibleMasker(detector_engine=detector_engine)
    response_scanner = ResponseScanner(detector_engine=detector_engine)
    injection_detector = PromptInjectionDetector()
    audit_logger = AuditLogger(db_path=db_path, salt=salt)
    llm_provider = provider or MockProvider()
    rate_limiter = RateLimiter(max_requests=100, window_seconds=60)

    # Attach instances to app state for testing and inspection
    app.state.policy_engine = policy_engine
    app.state.audit_logger = audit_logger
    app.state.llm_provider = llm_provider
    app.state.admin_key = admin_key

    @app.get("/health", response_model=HealthResponse)
    def health_check():
        return HealthResponse(
            status="healthy",
            active_policy=policy_engine.policy.name,
            provider=llm_provider.__class__.__name__,
        )

    @app.post("/v1/chat", response_model=ChatResponse)
    def chat_completion(request: ChatRequest):
        start_gateway_time = time.perf_counter()

        # 1. Rate limiting
        user_id = request.user_id or "anonymous"
        rate_limiter.check(user_id)

        # 2. Extract messages and latest user prompt
        raw_messages = [msg.model_dump() for msg in request.messages]
        user_prompts = [m["content"] for m in raw_messages if m.get("role") == "user"]
        latest_prompt = user_prompts[-1] if user_prompts else ""

        # 3. Stateless multi-turn detection and masking across all turns
        masked_messages, placeholder_map, detections_by_type = masker.mask_conversation(
            raw_messages
        )

        # 4. Prompt injection evaluation
        threshold = policy_engine.policy.injection_threshold
        injection_verdict = injection_detector.check(latest_prompt, threshold=threshold)

        # 5. Policy decision
        chosen_model = request.model or "mock-model"
        decision = policy_engine.evaluate_request(
            prompt=latest_prompt,
            model=chosen_model,
            user_group=request.user_group,
            injection_score=injection_verdict.risk_score,
            injection_reasons=injection_verdict.reasons,
            detections_by_type=detections_by_type,
        )

        # Record gateway latency before LLM dispatch
        inbound_gateway_latency = (time.perf_counter() - start_gateway_time) * 1000

        # Handle BLOCK decision
        if decision.action == DecisionAction.BLOCK:
            audit_logger.log_event(
                user_id=user_id,
                user_group=request.user_group or "general",
                policy_name=policy_engine.policy.name,
                prompt=latest_prompt,
                decision="BLOCK",
                decision_reason=decision.reason,
                detections_by_type=detections_by_type,
                injection_score=injection_verdict.risk_score,
                latency_ms=inbound_gateway_latency,
                model=chosen_model,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "Request blocked by AI Security Gateway",
                    "reason": decision.reason,
                    "violations": decision.violations,
                    "injection_score": injection_verdict.risk_score,
                },
            )

        # Determine messages to send to LLM
        dispatch_messages = (
            masked_messages if decision.action == DecisionAction.MASK else raw_messages
        )

        # 6. LLM Provider generation
        try:
            llm_response = llm_provider.generate(
                messages=dispatch_messages,
                model=chosen_model,
                temperature=request.temperature or 0.7,
                max_tokens=request.max_tokens or 1000,
            )
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"LLM provider generation error: {e}",
            ) from e

        # 7. Response scanning & sanitization
        start_outbound_time = time.perf_counter()
        scan_result = response_scanner.scan_response(llm_response.content, mask_violations=True)

        # 8. Unmask placeholders in completion back to original sensitive values
        final_content = masker.unmask_text(scan_result.sanitized_text, placeholder_map)
        outbound_latency = (time.perf_counter() - start_outbound_time) * 1000

        total_gateway_latency = inbound_gateway_latency + outbound_latency

        # 9. Audit logging
        audit_logger.log_event(
            user_id=user_id,
            user_group=request.user_group or "general",
            policy_name=policy_engine.policy.name,
            prompt=latest_prompt,
            decision=decision.action.value,
            decision_reason=decision.reason,
            detections_by_type=detections_by_type,
            injection_score=injection_verdict.risk_score,
            latency_ms=total_gateway_latency,
            model=chosen_model,
        )

        return ChatResponse(
            id=f"chatcmpl-{uuid.uuid4().hex[:12]}",
            model=chosen_model,
            choices=[
                ChatChoice(
                    index=0,
                    message=ChatMessage(role="assistant", content=final_content),
                    finish_reason="stop",
                )
            ],
            decision=decision.action.value,
            masked_entities=detections_by_type,
            injection_score=injection_verdict.risk_score,
            gateway_latency_ms=round(total_gateway_latency, 2),
        )

    admin_verifier = create_admin_verifier(admin_key)

    @app.get("/v1/audit", response_model=AuditQueryResponse)
    def get_audit_logs(
        limit: int = Query(50, ge=1, le=500),
        offset: int = Query(0, ge=0),
        decision: Optional[str] = Query(None),
        user_id: Optional[str] = Query(None),
        _admin_auth: bool = Depends(admin_verifier),
    ):
        logs = audit_logger.query_logs(
            limit=limit, offset=offset, decision=decision, user_id=user_id
        )
        return AuditQueryResponse(total=len(logs), logs=logs)

    return app
