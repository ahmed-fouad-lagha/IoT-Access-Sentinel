"""
Prometheus Metrics Module for IoT-Access-Sentinel
Inspired by AI_SOC's production metrics patterns

Provides comprehensive monitoring:
- Request counts and latency
- LLM token usage and costs
- Decision outcomes (ALLOW/DENY)
- Error tracking
"""

import time
import logging
from typing import Optional, Callable
from functools import wraps
from contextlib import contextmanager

try:
    from prometheus_client import Counter, Histogram, Gauge, Info, generate_latest, CONTENT_TYPE_LATEST
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False
    
logger = logging.getLogger(__name__)


class SentinelMetrics:
    """
    Prometheus metrics for IoT-Access-Sentinel.
    
    Tracks:
    - API request counts and latency
    - LLM inference metrics (tokens, latency, costs)
    - Decision outcomes (ALLOW/DENY by category)
    - Deterministic vs LLM path usage
    """
    
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if getattr(self, '_initialized', False):
            return
            
        if not PROMETHEUS_AVAILABLE:
            logger.warning("prometheus_client not installed. Metrics disabled.")
            self._initialized = True
            return
        
        # Service info
        self.info = Info(
            'sentinel_info',
            'IoT-Access-Sentinel service information'
        )
        
        # Request metrics
        self.requests_total = Counter(
            'sentinel_requests_total',
            'Total access control requests',
            ['method', 'endpoint', 'status']
        )
        
        self.request_duration = Histogram(
            'sentinel_request_duration_seconds',
            'Request duration in seconds',
            ['endpoint'],
            buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]
        )
        
        # Decision metrics
        self.decisions_total = Counter(
            'sentinel_decisions_total',
            'Total access decisions',
            ['action', 'category', 'path']  # action: ALLOW/DENY, path: deterministic/llm
        )
        
        self.decision_confidence = Histogram(
            'sentinel_decision_confidence',
            'Decision confidence distribution',
            ['action'],
            buckets=[0.5, 0.6, 0.7, 0.8, 0.9, 0.95, 0.99, 1.0]
        )
        
        # LLM metrics
        self.llm_requests_total = Counter(
            'sentinel_llm_requests_total',
            'Total LLM API requests',
            ['model', 'status']  # status: success/error/timeout
        )
        
        self.llm_tokens_total = Counter(
            'sentinel_llm_tokens_total',
            'Total LLM tokens consumed',
            ['model', 'type']  # type: prompt/completion
        )
        
        self.llm_latency = Histogram(
            'sentinel_llm_latency_seconds',
            'LLM inference latency',
            ['model'],
            buckets=[0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0]
        )
        
        self.llm_cost_dollars = Counter(
            'sentinel_llm_cost_dollars',
            'Estimated LLM API cost in dollars',
            ['model']
        )
        
        # Path metrics (deterministic vs LLM)
        self.deterministic_decisions = Counter(
            'sentinel_deterministic_decisions_total',
            'Requests handled by deterministic validator',
            ['result']  # result: deny/pass_to_llm
        )
        
        # Error metrics
        self.errors_total = Counter(
            'sentinel_errors_total',
            'Total errors by type',
            ['error_type']
        )
        
        # Active requests gauge
        self.active_requests = Gauge(
            'sentinel_active_requests',
            'Currently processing requests'
        )
        
        self._initialized = True
        logger.info("Prometheus metrics initialized for IoT-Access-Sentinel")
    
    def record_request(self, method: str, endpoint: str, status: str, duration: float):
        """Record HTTP request metrics."""
        if not PROMETHEUS_AVAILABLE:
            return
        self.requests_total.labels(method=method, endpoint=endpoint, status=status).inc()
        self.request_duration.labels(endpoint=endpoint).observe(duration)
    
    def record_decision(self, action: str, category: str, path: str, confidence: float):
        """
        Record access control decision.
        
        Args:
            action: ALLOW or DENY
            category: user_auth, time_network, device_specific, attack, edge_case
            path: deterministic or llm
            confidence: Decision confidence 0.0-1.0
        """
        if not PROMETHEUS_AVAILABLE:
            return
        self.decisions_total.labels(action=action, category=category, path=path).inc()
        self.decision_confidence.labels(action=action).observe(confidence)
    
    def record_llm_request(
        self, 
        model: str, 
        status: str, 
        latency: float,
        prompt_tokens: int = 0,
        completion_tokens: int = 0
    ):
        """
        Record LLM API request.
        
        Args:
            model: Model identifier (e.g., llama-3.3-70b-versatile)
            status: success, error, timeout
            latency: Inference time in seconds
            prompt_tokens: Input tokens
            completion_tokens: Output tokens
        """
        if not PROMETHEUS_AVAILABLE:
            return
            
        self.llm_requests_total.labels(model=model, status=status).inc()
        self.llm_latency.labels(model=model).observe(latency)
        
        if prompt_tokens > 0:
            self.llm_tokens_total.labels(model=model, type='prompt').inc(prompt_tokens)
        if completion_tokens > 0:
            self.llm_tokens_total.labels(model=model, type='completion').inc(completion_tokens)
        
        # Estimate cost (Groq pricing: $0.59/M input, $0.79/M output)
        cost = (prompt_tokens * 0.59 / 1_000_000) + (completion_tokens * 0.79 / 1_000_000)
        if cost > 0:
            self.llm_cost_dollars.labels(model=model).inc(cost)
    
    def record_deterministic_decision(self, result: str):
        """Record deterministic validator outcome (deny or pass_to_llm)."""
        if not PROMETHEUS_AVAILABLE:
            return
        self.deterministic_decisions.labels(result=result).inc()
    
    def record_error(self, error_type: str):
        """Record error by type (timeout, validation, llm_failure, etc.)."""
        if not PROMETHEUS_AVAILABLE:
            return
        self.errors_total.labels(error_type=error_type).inc()
    
    @contextmanager
    def track_request(self, endpoint: str):
        """Context manager for tracking request duration and active count."""
        if not PROMETHEUS_AVAILABLE:
            yield
            return
            
        self.active_requests.inc()
        start_time = time.time()
        try:
            yield
        finally:
            duration = time.time() - start_time
            self.active_requests.dec()
            self.request_duration.labels(endpoint=endpoint).observe(duration)
    
    def set_info(self, version: str, environment: str = "production"):
        """Set service metadata."""
        if not PROMETHEUS_AVAILABLE:
            return
        self.info.info({
            'version': version,
            'environment': environment,
            'framework': 'hybrid_llm'
        })


# Global metrics instance
metrics = SentinelMetrics()


def get_metrics_endpoint():
    """FastAPI endpoint for Prometheus scraping."""
    if not PROMETHEUS_AVAILABLE:
        return "prometheus_client not installed"
    return generate_latest()


def timed(endpoint: str):
    """Decorator to time function execution."""
    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            with metrics.track_request(endpoint):
                return await func(*args, **kwargs)
        return wrapper
    return decorator
