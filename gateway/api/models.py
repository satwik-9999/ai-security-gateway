"""Pydantic request and response schemas for FastAPI endpoints."""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ChatMessage(BaseModel):
    role: str
    content: str


class ChatRequest(BaseModel):
    messages: List[ChatMessage]
    model: Optional[str] = "gemini-2.5-flash-lite"
    user_id: Optional[str] = "default_user"
    user_group: Optional[str] = "general"
    temperature: Optional[float] = 0.7
    max_tokens: Optional[int] = 1000


class ChatChoice(BaseModel):
    index: int = 0
    message: ChatMessage
    finish_reason: str = "stop"


class ChatResponse(BaseModel):
    id: str
    model: str
    choices: List[ChatChoice]
    decision: str
    masked_entities: Dict[str, int] = Field(default_factory=dict)
    injection_score: float = 0.0
    gateway_latency_ms: float = 0.0


class HealthResponse(BaseModel):
    status: str = "healthy"
    active_policy: str
    provider: str
    version: str = "0.1.0"


class AuditQueryResponse(BaseModel):
    total: int
    logs: List[Dict[str, Any]]
