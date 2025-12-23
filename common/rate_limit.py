"""
Rate Limiting Middleware for IoT-Access-Sentinel
Inspired by AI_SOC's sliding window rate limiter

Protects against:
- DoS attacks
- LLM API abuse
- Ensures fair resource usage
"""

import time
import logging
from typing import Optional, Dict, Callable
from collections import defaultdict, deque

from fastapi import Request, HTTPException, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)


class SlidingWindowRateLimiter:
    """
    Sliding window rate limiter with per-client tracking.
    
    Features:
    - Per-IP and per-API-key limits
    - Automatic cleanup of old entries
    - Thread-safe design
    """
    
    def __init__(
        self,
        requests_per_window: int,
        window_seconds: int,
        cleanup_interval: int = 300
    ):
        self.requests_per_window = requests_per_window
        self.window_seconds = window_seconds
        self.cleanup_interval = cleanup_interval
        
        # Store: client_id -> deque of timestamps
        self.request_log: Dict[str, deque] = defaultdict(deque)
        self.last_cleanup = time.time()
        
        logger.info(f"Rate limiter: {requests_per_window} req/{window_seconds}s")
    
    def _cleanup_old_entries(self):
        """Remove expired entries from memory."""
        current_time = time.time()
        
        if current_time - self.last_cleanup < self.cleanup_interval:
            return
        
        cutoff_time = current_time - self.window_seconds
        cleaned = 0
        
        # Iterate over copy of keys to safely delete during iteration
        for client_id in list(self.request_log.keys()):
            timestamps = self.request_log[client_id]
            while timestamps and timestamps[0] < cutoff_time:
                timestamps.popleft()
            if not timestamps:
                del self.request_log[client_id]
                cleaned += 1
        
        self.last_cleanup = current_time
        if cleaned > 0:
            logger.debug(f"Cleaned {cleaned} inactive clients")
    
    def is_allowed(self, client_id: str) -> tuple[bool, Optional[float]]:
        """
        Check if request is allowed.
        
        Returns:
            (is_allowed, retry_after_seconds)
        """
        current_time = time.time()
        cutoff_time = current_time - self.window_seconds
        
        self._cleanup_old_entries()
        
        timestamps = self.request_log[client_id]
        
        # Remove expired
        while timestamps and timestamps[0] < cutoff_time:
            timestamps.popleft()
        
        # Check limit
        if len(timestamps) >= self.requests_per_window:
            retry_after = timestamps[0] + self.window_seconds - current_time
            logger.warning(f"Rate limit exceeded for {client_id}")
            return False, max(0, retry_after)
        
        timestamps.append(current_time)
        return True, None
    
    def get_remaining(self, client_id: str) -> int:
        """Get remaining requests for client."""
        current_time = time.time()
        cutoff_time = current_time - self.window_seconds
        
        timestamps = self.request_log.get(client_id, deque())
        valid_count = sum(1 for ts in timestamps if ts > cutoff_time)
        
        return max(0, self.requests_per_window - valid_count)


# Common endpoints to skip rate limiting
HEALTH_ENDPOINTS = ["/health", "/metrics", "/docs", "/openapi.json"]

class RateLimitMiddleware(BaseHTTPMiddleware):
    """FastAPI middleware for rate limiting."""
    
    def __init__(
        self,
        app,
        default_limit: int = 100,
        default_window: int = 60,
        endpoint_limits: Optional[Dict[str, tuple[int, int]]] = None
    ):
        super().__init__(app)
        
        self.default_limiter = SlidingWindowRateLimiter(default_limit, default_window)
        self.endpoint_limiters: Dict[str, SlidingWindowRateLimiter] = {}
        
        if endpoint_limits:
            for path, (limit, window) in endpoint_limits.items():
                self.endpoint_limiters[path] = SlidingWindowRateLimiter(limit, window)
        
        logger.info(f"Rate limit middleware: default={default_limit}/{default_window}s")
    
    def _get_client_id(self, request: Request) -> str:
        """Extract client identifier from request."""
        # Check for API key
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header.replace("Bearer ", "")
            return f"key:{token[:20]}"
        
        # Check forwarded IP (behind proxy)
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        
        return request.client.host if request.client else "unknown"
    
    async def dispatch(self, request: Request, call_next):
        """Process request through rate limiter."""
        # Skip for health/metrics endpoints
        if request.url.path in HEALTH_ENDPOINTS:
            return await call_next(request)
        
        client_id = self._get_client_id(request)
        
        limiter = self.endpoint_limiters.get(
            request.url.path,
            self.default_limiter
        )
        
        is_allowed, retry_after = limiter.is_allowed(client_id)
        
        if not is_allowed:
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "error": "Rate limit exceeded",
                    "detail": f"Retry after {int(retry_after)} seconds",
                    "retry_after": int(retry_after)
                },
                headers={
                    "Retry-After": str(int(retry_after)),
                    "X-RateLimit-Limit": str(limiter.requests_per_window),
                    "X-RateLimit-Remaining": "0"
                }
            )
        
        response = await call_next(request)
        
        # Add rate limit headers
        remaining = limiter.get_remaining(client_id)
        response.headers["X-RateLimit-Limit"] = str(limiter.requests_per_window)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        
        return response


# Pre-configured profiles
RATE_LIMIT_PROFILES = {
    "strict": {  # For production with limited LLM budget
        "default_limit": 30,
        "default_window": 60,
        "endpoint_limits": {
            "/access-control": (20, 60),  # 20 decisions/min
            "/health": (120, 60)
        }
    },
    "moderate": {  # Default
        "default_limit": 100,
        "default_window": 60,
        "endpoint_limits": {
            "/access-control": (60, 60),
            "/health": (120, 60)
        }
    },
    "development": {  # For testing
        "default_limit": 1000,
        "default_window": 60,
        "endpoint_limits": {}
    }
}


def create_rate_limiter(app, profile: str = "moderate"):
    """Factory function to create rate limit middleware."""
    config = RATE_LIMIT_PROFILES.get(profile, RATE_LIMIT_PROFILES["moderate"])
    return RateLimitMiddleware(app, **config)
