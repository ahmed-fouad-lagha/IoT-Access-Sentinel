"""
Activity Tracer for IoT-Access-Sentinel
Inspired by PentestGPT's tracer pattern

Provides:
- Audit trail for all decisions
- Tool execution tracking
- Reproducibility for paper documentation
"""

import threading
import json
from datetime import datetime
from typing import Any, Callable, Optional, List, Dict
from pathlib import Path

import structlog

logger = structlog.get_logger(__name__)


class DecisionTracer:
    """
    Thread-safe tracer for tracking decision pipeline activity.
    
    Records:
    - Alert ingestion
    - Deterministic validation results
    - LLM agent invocations
    - Final decisions and enforcement
    """
    
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
            
        self._lock = threading.Lock()
        self._activities: List[Dict[str, Any]] = []
        self._on_activity_callback: Optional[Callable[[Dict[str, Any]], None]] = None
        self._session_id: Optional[str] = None
        self._initialized = True
    
    def start_session(self, session_id: str = None) -> str:
        """Start a new tracing session."""
        if session_id is None:
            session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        with self._lock:
            self._session_id = session_id
            self._activities.clear()
        
        self._track({
            "type": "session_start",
            "session_id": session_id
        })
        
        return session_id
    
    def _track(self, activity: Dict[str, Any]) -> int:
        """Internal method to record activity."""
        activity["timestamp"] = datetime.now().isoformat()
        activity["session_id"] = self._session_id
        
        with self._lock:
            activity_id = len(self._activities)
            activity["id"] = activity_id
            self._activities.append(activity)
        
        if self._on_activity_callback:
            self._on_activity_callback(activity)
        
        return activity_id
    
    def track_alert_received(
        self,
        alert_id: str,
        device_type: str,
        source_ip: str,
        user_id: Optional[str] = None
    ) -> int:
        """Track incoming alert."""
        return self._track({
            "type": "alert_received",
            "alert_id": alert_id,
            "device_type": device_type,
            "source_ip": source_ip,
            "user_id": user_id
        })
    
    def track_deterministic_check(
        self,
        check_name: str,
        passed: bool,
        details: Optional[str] = None
    ) -> int:
        """Track deterministic validation step."""
        return self._track({
            "type": "deterministic_check",
            "check_name": check_name,
            "passed": passed,
            "details": details
        })
    
    def track_llm_invocation(
        self,
        agent_name: str,
        model: str,
        prompt_tokens: int,
        completion_tokens: int,
        latency_ms: float
    ) -> int:
        """Track LLM agent invocation."""
        return self._track({
            "type": "llm_invocation",
            "agent_name": agent_name,
            "model": model,
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "latency_ms": latency_ms
        })
    
    def track_decision(
        self,
        action: str,
        confidence: float,
        reasoning: str,
        path: str  # "deterministic" or "llm"
    ) -> int:
        """Track final decision."""
        return self._track({
            "type": "decision",
            "action": action,
            "confidence": confidence,
            "reasoning": reasoning,
            "decision_path": path
        })
    
    def track_enforcement(
        self,
        action: str,
        target_ip: str,
        agent_id: Optional[str] = None,
        success: bool = True
    ) -> int:
        """Track enforcement action."""
        return self._track({
            "type": "enforcement",
            "action": action,
            "target_ip": target_ip,
            "agent_id": agent_id,
            "success": success
        })
    
    def track_error(
        self,
        error_type: str,
        message: str,
        context: Optional[Dict] = None
    ) -> int:
        """Track error occurrence."""
        return self._track({
            "type": "error",
            "error_type": error_type,
            "message": message,
            "context": context or {}
        })
    
    def set_callback(self, callback: Callable[[Dict[str, Any]], None]):
        """Set callback for real-time activity notifications."""
        self._on_activity_callback = callback
    
    def get_activities(self, count: int = 50) -> List[Dict[str, Any]]:
        """Get recent activities."""
        with self._lock:
            return self._activities[-count:] if self._activities else []
    
    def get_session_summary(self) -> Dict[str, Any]:
        """Get summary of current session."""
        with self._lock:
            activities = self._activities.copy()
        
        if not activities:
            return {"session_id": self._session_id, "activities": 0}
        
        decisions = [a for a in activities if a["type"] == "decision"]
        llm_calls = [a for a in activities if a["type"] == "llm_invocation"]
        errors = [a for a in activities if a["type"] == "error"]
        
        total_tokens = sum(
            a.get("prompt_tokens", 0) + a.get("completion_tokens", 0)
            for a in llm_calls
        )
        
        return {
            "session_id": self._session_id,
            "total_activities": len(activities),
            "decisions": len(decisions),
            "llm_calls": len(llm_calls),
            "total_tokens": total_tokens,
            "errors": len(errors),
            "allow_count": sum(1 for d in decisions if d.get("action") == "ALLOW"),
            "deny_count": sum(1 for d in decisions if d.get("action") == "DENY")
        }
    
    def export_to_json(self, filepath: str = None) -> str:
        """Export activities to JSON file."""
        if filepath is None:
            filepath = f"trace_{self._session_id or 'default'}.json"
        
        with self._lock:
            data = {
                "session_id": self._session_id,
                "export_time": datetime.now().isoformat(),
                "summary": self.get_session_summary(),
                "activities": self._activities
            }
        
        Path(filepath).write_text(json.dumps(data, indent=2, default=str))
        logger.info(f"Exported trace to {filepath}")
        
        return filepath
    
    def clear(self):
        """Clear all activities."""
        with self._lock:
            self._activities.clear()


# Global tracer instance
tracer = DecisionTracer()


def get_tracer() -> DecisionTracer:
    """Get the global tracer instance."""
    return tracer
