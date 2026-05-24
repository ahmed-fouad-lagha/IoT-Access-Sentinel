"""
Common Schemas - IoT-Access-Sentinel
Shared data models for access decisions and enforcement actions
"""

from pydantic import BaseModel, Field
from typing import Optional, Literal
from datetime import datetime, timezone


class AccessDecision(BaseModel):
    """Decision output from the LLM decision engine"""
    
    action: Literal["ALLOW", "DENY", "ERROR"] = Field(
        ...,
        description="Final access control decision"
    )
    
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Confidence score of the decision (0.0-1.0)"
    )
    
    reason: str = Field(
        ...,
        description="Human-readable explanation of the decision"
    )
    
    policy_matched: Optional[str] = Field(
        None,
        description="Name of the policy that was matched"
    )
    
    context_analysis: Optional[dict] = Field(
        None,
        description="Context analysis from Context Agent"
    )
    
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Decision timestamp"
    )


class EnforcementAction(BaseModel):
    """Enforcement action to be executed"""
    
    action_type: Literal["BLOCK_IP", "ISOLATE_DEVICE", "RATE_LIMIT", "ALERT_ONLY"] = Field(
        ...,
        description="Type of enforcement action"
    )
    
    target: str = Field(
        ...,
        description="Target of enforcement (IP address, device ID, etc.)"
    )
    
    duration: Optional[int] = Field(
        None,
        description="Duration of enforcement in seconds (None = permanent)"
    )
    
    reason: str = Field(
        ...,
        description="Reason for enforcement"
    )
    
    agent_id: Optional[str] = Field(
        None,
        description="Wazuh agent ID for remote enforcement"
    )
    
    alert_id: Optional[str] = Field(
        None,
        description="Associated alert ID for tracking"
    )
    
    executed: bool = Field(
        default=False,
        description="Whether the action was successfully executed"
    )
    
    execution_result: Optional[str] = Field(
        None,
        description="Result message from enforcement execution"
    )
    
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Action timestamp"
    )
