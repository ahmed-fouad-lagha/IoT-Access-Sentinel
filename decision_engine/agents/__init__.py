"""
Agent definitions for decision engine
Contains Policy Agent and Context Agent for access control decisions
Updated to use direct OpenAI SDK calls
"""

from .policy_agent import call_policy_agent, POLICY_AGENT_SYSTEM_MESSAGE
from .context_agent import call_context_agent, CONTEXT_AGENT_SYSTEM_MESSAGE

__all__ = ["call_policy_agent", "call_context_agent", "POLICY_AGENT_SYSTEM_MESSAGE", "CONTEXT_AGENT_SYSTEM_MESSAGE"]
