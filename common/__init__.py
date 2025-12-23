"""
Common utilities package for IoT-Access-Sentinel

Production-grade modules:
- metrics: Prometheus monitoring
- rate_limit: DoS protection
- tracer: Audit trails
- validation: Input sanitization
"""

from .metrics import metrics, SentinelMetrics, get_metrics_endpoint, timed
from .rate_limit import RateLimitMiddleware, create_rate_limiter, RATE_LIMIT_PROFILES
from .tracer import tracer, get_tracer, DecisionTracer
from .validation import validator, validate_alert, InputValidator, ValidationResult

__all__ = [
    # Metrics
    "metrics",
    "SentinelMetrics", 
    "get_metrics_endpoint",
    "timed",
    
    # Rate limiting
    "RateLimitMiddleware",
    "create_rate_limiter",
    "RATE_LIMIT_PROFILES",
    
    # Tracing
    "tracer",
    "get_tracer",
    "DecisionTracer",
    
    # Validation
    "validator",
    "validate_alert",
    "InputValidator",
    "ValidationResult",
]
