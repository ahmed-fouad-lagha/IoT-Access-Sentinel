"""
Decision Pipeline - IoT-Access-Sentinel Decision Engine
Orchestrates Policy and Context agents to make access control decisions
"""

import json
import yaml
from typing import Dict, Any
from datetime import datetime

from config.settings import Settings
from common.schemas import AccessDecision
from common.logging_config import get_logger
from .agents import call_policy_agent, call_context_agent
from .llm_client import get_llm_client
from observer.models import IoTAccessAlert

logger = get_logger(__name__)


class DecisionPipeline:
    """
    Orchestrates multi-agent decision making for IoT access control
    """
    
    def __init__(self, settings: Settings):
        """
        Initialize decision pipeline with agents
        
        Args:
            settings: Application settings
        """
        self.settings = settings
        self.llm_client = get_llm_client(settings)
        self.model = settings.llm_model
        self.provider = settings.llm_provider.lower()
        
        # Load access policies
        self.policies = self._load_policies()
        
        logger.info("decision_pipeline_initialized", num_policies=len(self.policies.get("policies", [])), model=self.model, provider=self.provider)
    
    def _load_policies(self) -> Dict[str, Any]:
        """Load access policies from YAML file"""
        try:
            with open(self.settings.policy_file_path, 'r') as f:
                policies = yaml.safe_load(f)
            logger.info("policies_loaded", file=self.settings.policy_file_path)
            return policies
        except Exception as e:
            logger.error("policy_load_failed", error=str(e))
            return {"policies": [], "default_policy": {"action": "DENY", "alert": True}}
    
    async def make_decision(self, alert: IoTAccessAlert) -> AccessDecision:
        """
        Make access control decision using multi-agent pipeline
        
        Args:
            alert: IoT access alert from Wazuh
        
        Returns:
            AccessDecision with action, confidence, and reasoning
        """
        logger.info("making_decision", alert_id=alert.id, device_type=alert.device_type)
        
        try:
            # Step 1: Context Analysis
            context_analysis = await self._analyze_context(alert)
            
            # Step 2: Policy Decision (with context as input)
            policy_decision = await self._evaluate_policy(alert, context_analysis)
            
            # Step 3: Combine results into AccessDecision
            decision = AccessDecision(
                action=policy_decision["action"],
                confidence=policy_decision["confidence"],
                reason=policy_decision["reason"],
                policy_matched=policy_decision.get("policy_matched"),
                context_analysis=context_analysis,
                timestamp=datetime.utcnow()
            )
            
            logger.info(
                "decision_made",
                alert_id=alert.id,
                action=decision.action,
                confidence=decision.confidence
            )
            
            return decision
            
        except Exception as e:
            logger.error("decision_failed", alert_id=alert.id, error=str(e))
            # Fail-safe: DENY on error
            return AccessDecision(
                action="DENY",
                confidence=1.0,
                reason=f"Decision pipeline error: {str(e)}",
                policy_matched="error_fallback",
                timestamp=datetime.utcnow()
            )
    
    async def _analyze_context(self, alert: IoTAccessAlert) -> Dict[str, Any]:
        """
        Use Context Agent to analyze connection context
        
        Args:
            alert: IoT access alert
        
        Returns:
            Context analysis dictionary
        """
        context_prompt = f"""Analyze the context of this IoT connection attempt:

Device Type: {alert.device_type or 'Unknown'}
Device ID: {alert.device_id or 'Unknown'}
Source IP: {alert.source_ip or 'Unknown'}
Destination: {alert.destination_ip}:{alert.destination_port}
Protocol: {alert.protocol or 'Unknown'}
Timestamp: {alert.timestamp}
Current Time: {datetime.utcnow().isoformat()}

Wazuh Rule: {alert.rule.description} (Level {alert.rule.level})

Provide your context analysis in JSON format, then TERMINATE.
"""
        
        # Call context agent with provider
        result = await call_context_agent(self.llm_client, self.model, context_prompt, self.provider)
        
        # Parse JSON response
        try:
            # Extract JSON from response
            response_text = result if isinstance(result, str) else str(result)
            # Find JSON in response (may have extra text before/after)
            json_start = response_text.find("{")
            json_end = response_text.rfind("}") + 1
            if json_start >= 0 and json_end > json_start:
                context_data = json.loads(response_text[json_start:json_end])
            else:
                logger.warning("context_agent_no_json", response=response_text)
                context_data = {"risk_score": 0.5, "anomalies_detected": [], "context_summary": "Parse error"}
        except json.JSONDecodeError as e:
            logger.error("context_agent_json_error", error=str(e), response=result)
            context_data = {"risk_score": 0.5, "anomalies_detected": [], "context_summary": "JSON parse error"}
        
        return context_data
    
    async def _evaluate_policy(self, alert: IoTAccessAlert, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Use Policy Agent to evaluate access policies
        
        Args:
            alert: IoT access alert
            context: Context analysis from Context Agent
        
        Returns:
            Policy decision dictionary
        """
        # Format policies for the agent
        policies_text = yaml.dump(self.policies, default_flow_style=False)
        
        policy_prompt = f"""Evaluate this IoT connection against access policies:

**Connection Details:**
Device Type: {alert.device_type or 'Unknown'}
Device ID: {alert.device_id or 'Unknown'}
Source IP: {alert.source_ip or 'Unknown'}
Timestamp: {alert.timestamp}

**Context Analysis:**
Risk Score: {context.get('risk_score', 0.5)}
Anomalies: {context.get('anomalies_detected', [])}
Summary: {context.get('context_summary', 'No context')}

**Access Policies:**
{policies_text}

Make your access decision in JSON format, then TERMINATE.
"""
        
        result = await call_policy_agent(self.llm_client, self.model, policy_prompt, self.provider)
        
        # Parse JSON response
        try:
            response_text = result if isinstance(result, str) else str(result)
            json_start = response_text.find("{")
            json_end = response_text.rfind("}") + 1
            if json_start >= 0 and json_end > json_start:
                policy_data = json.loads(response_text[json_start:json_end])
            else:
                logger.warning("policy_agent_no_json", response=response_text)
                policy_data = {"action": "DENY", "confidence": 1.0, "reason": "Parse error - fail safe", "policy_matched": "error"}
        except json.JSONDecodeError as e:
            logger.error("policy_agent_json_error", error=str(e), response=result)
            policy_data = {"action": "DENY", "confidence": 1.0, "reason": "JSON parse error - fail safe", "policy_matched": "error"}
        
        return policy_data
