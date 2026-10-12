"""Security middleware: rate limiting and admin authentication."""

import time
from typing import Callable, Dict, List, Optional

from fastapi import Header, HTTPException, status


class RateLimiter:
    """In-memory sliding window rate limiter."""

    def __init__(self, max_requests: int = 60, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.user_requests: Dict[str, List[float]] = {}

    def check(self, user_id: str):
        now = time.time()
        window_start = now - self.window_seconds

        if user_id not in self.user_requests:
            self.user_requests[user_id] = [now]
            return

        # Prune old timestamps
        timestamps = [t for t in self.user_requests[user_id] if t > window_start]
        if len(timestamps) >= self.max_requests:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded: maximum {self.max_requests} requests per {self.window_seconds} seconds.",
            )

        timestamps.append(now)
        self.user_requests[user_id] = timestamps


def create_admin_verifier(configured_key: str) -> Callable:
    """Creates a FastAPI dependency function that validates X-Admin-Key header against configured_key."""

    def verify_admin_key(x_admin_key: Optional[str] = Header(None, alias="X-Admin-Key")) -> bool:
        if not x_admin_key or x_admin_key != configured_key:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or missing X-Admin-Key authentication header.",
            )
        return True

    return verify_admin_key
