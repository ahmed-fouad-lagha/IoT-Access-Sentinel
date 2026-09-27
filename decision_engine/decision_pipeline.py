"""
Decision Pipeline - IoT-Access-Sentinel Decision Engine
Orchestrates Policy and Context agents to make access control decisions

Hybrid Architecture:
- Step 0: Deterministic user authorization validation (Python code)
- Step 1: Context analysis (LLM)
- Step 2: Policy evaluation (LLM with context)
"""

import asyncio
import json
import yaml
import hashlib
import ipaddress
import time
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime, timezone, timedelta
from collections import defaultdict
from cachetools import TTLCache
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from openai import RateLimitError, APIConnectionError, APITimeoutError

from config.settings import Settings
from common.schemas import AccessDecision
from common.logging_config import get_logger
from common.validation import sanitize_secrets
from .agents import call_policy_agent, call_context_agent
from .llm_client import get_llm_client
from .validators import get_user_auth_validator
from .prompt_guard import scan_alert
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
        
        # Load policies
        self.policies = self._load_policies()

        # Initialize semantic cache with TTL (1 hour) and max size (1000 items)
        self.cache = TTLCache(maxsize=1000, ttl=3600)
        self.cache_hits = 0
        self.cache_misses = 0
        self.use_single_agent = settings.use_single_agent
        
        # Per-IP rate limiter for LLM invocations (DoS mitigation)
        # Sliding window: max N LLM invocations per source IP per window
        self.rate_limit_enabled = getattr(settings, 'rate_limit_enabled', False)
        self.rate_limit_window_s = getattr(settings, 'rate_limit_window_s', 60)
        self.rate_limit_max_requests = getattr(settings, 'rate_limit_max_requests', 10)
        self._rate_limit_tracker: Dict[str, List[float]] = defaultdict(list)
        
        # Load prompts
        self.prompts = self._load_prompts()
        
        logger.info("decision_pipeline_initialized", num_policies=len(self.policies.get("policies", [])), model=self.model, provider=self.provider, rate_limit_enabled=self.rate_limit_enabled)
    
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
    
    def _load_prompts(self) -> Dict[str, str]:
        """Load LLM prompts from external files"""
        prompts = {}
        import os
        prompt_dir = os.path.join(os.path.dirname(__file__), "prompts")
        
        try:
            with open(os.path.join(prompt_dir, "context_agent.txt"), "r") as f:
                prompts["context"] = f.read()
            with open(os.path.join(prompt_dir, "policy_agent.txt"), "r") as f:
                prompts["policy"] = f.read()
            logger.info("prompts_loaded", dir=prompt_dir)
        except Exception as e:
            logger.warning("prompt_load_failed_using_fallbacks", error=str(e))
            # Fallback for robustness
            prompts["context"] = (
                "Analyze the context of this connection attempt:\n"
                "Device Type: {device_type}\n"
                "Device ID: {device_id}\n"
                "Source: {source_ip}\n"
                "Rule: {rule_description}\n"
                "Level: {rule_level}\n"
                "Return only JSON with risk_score and anomalies_detected."
            )
            prompts["policy"] = (
                "Evaluate this connection request against policies:\n"
                "Device Type: {device_type}\n"
                "Device ID: {device_id}\n"
                "User ID: {user_id}\n"
                "Risk Score: {risk_score}\n"
                "Context Summary: {context_summary}\n"
                "Policies:\n{policies}\n"
                "Return ALLOW or DENY in JSON format."
            )
            
        return prompts
    
    async def make_decision(self, alert: IoTAccessAlert) -> AccessDecision:
        """
        Make access control decision using hybrid pipeline:
        1. Deterministic user authorization check (fail-fast)
        1b. Prompt Guard: injection scan on user-supplied fields
        2. Semantic cache lookup
        3. LLM context analysis
        4. LLM policy evaluation
        
        Args:
            alert: IoT access alert from Wazuh
        
        Returns:
            AccessDecision with action, confidence, and reasoning
        """
        logger.info("making_decision", alert_id=alert.id, device_type=alert.device_type)
        
        try:
            # Step 0: User Authorization Pre-Check (M0801)
            # This is deterministic and runs BEFORE the LLM
            user_auth_result = self._validate_user_authorization(alert)
            
            if not user_auth_result.authorized:
                # User authorization failed - DENY immediately without LLM
                logger.info(
                    "user_authorization_denied",
                    alert_id=alert.id,
                    reason=user_auth_result.reason
                )
                return AccessDecision(
                    action="DENY",
                    confidence=1.0,
                    reason=f"User authorization failed: {user_auth_result.reason}",
                    policy_matched="user_authorization_check",
                    timestamp=datetime.now(timezone.utc)
                )
            
            # User authorized (or not required) - proceed to LLM analysis
            logger.info(
                "user_authorization_passed",
                alert_id=alert.id,
                reason=user_auth_result.reason
            )

            # Per-IP rate limit check before LLM invocation (DoS mitigation)
            if self.rate_limit_enabled and alert.source_ip:
                if self._is_rate_limited(alert.source_ip):
                    logger.warning(
                        "rate_limit_exceeded",
                        alert_id=alert.id,
                        source_ip=alert.source_ip
                    )
                    return AccessDecision(
                        action="DENY",
                        confidence=1.0,
                        reason=f"Rate limit exceeded for source IP {alert.source_ip}. "
                               f"Max {self.rate_limit_max_requests} LLM invocations per "
                               f"{self.rate_limit_window_s}s window.",
                        policy_matched="rate_limit_dos_mitigation",
                        timestamp=datetime.now(timezone.utc)
                    )

            # Enrich alert metadata from user authorization results
            if user_auth_result.matched_role and not alert.user_role:
                alert.user_role = user_auth_result.matched_role
            if user_auth_result.token_status:
                if user_auth_result.token_status == "VALID":
                    alert.auth_token = "VALID (Cryptographically Verified)"
                elif user_auth_result.token_status == "NOT_REQUIRED":
                    alert.auth_token = "NOT REQUIRED"
                elif user_auth_result.token_status == "MISSING":
                    alert.auth_token = "MISSING"
                elif user_auth_result.token_status == "INVALID":
                    alert.auth_token = "INVALID"
                else:
                    alert.auth_token = str(user_auth_result.token_status)

            # Run deterministic temporal and network checks
            policy = self._get_policy(alert.device_type)
            time_check_status = "PASS"
            network_check_status = "PASS"
            
            if policy:
                # 1. Temporal Check
                allowed_hours = policy.get('allowed_hours')
                allowed_days = policy.get('allowed_days')
                if allowed_hours and alert.timestamp:
                    time_ok, time_reason = self._check_time_policy(alert.timestamp, allowed_hours, allowed_days)
                    if not time_ok:
                        time_check_status = f"FAIL ({time_reason})"
                
                # 2. Network Check
                allowed_networks = policy.get('allowed_source_networks')
                if allowed_networks and alert.source_ip:
                    net_ok, net_reason = self._check_network_policy(alert.source_ip, allowed_networks)
                    if not net_ok:
                        network_check_status = f"FAIL ({net_reason})"

            # Step 0b: Prompt Guard — injection scan on all user-supplied text fields
            # Two layers: deterministic regex (instant) + ML guard model (async)
            # Runs BEFORE cache lookup so injections never get cached.
            guard_result = await scan_alert(
                client=self.llm_client,
                alert_fields={
                    "rule_description": alert.rule.description,
                    "device_id": alert.device_id,
                    "user_id": alert.user_id,
                    "user_role": alert.user_role,
                }
            )
            if guard_result.is_injection:
                logger.warning(
                    "prompt_guard_injection_blocked",
                    alert_id=alert.id,
                    reason=guard_result.reason
                )
                return AccessDecision(
                    action="DENY",
                    confidence=1.0,
                    reason=f"Prompt injection detected: {guard_result.reason}",
                    policy_matched="prompt_guard",
                    timestamp=datetime.now(timezone.utc)
                )

            # --- SEMANTIC CACHE LOOKUP ---
            # Build granular cache key to prevent security bypasses
            device_type = alert.device_type or "unknown"
            device_id = alert.device_id or "unknown"
            user_id = alert.user_id or "unknown"
            source_ip = alert.source_ip or "unknown"
            dest_ip = alert.destination_ip or "unknown"
            dest_port = alert.destination_port or "unknown"
            protocol = alert.protocol or "unknown"
            rule_desc = alert.rule.description or "unknown"
            # Increased granularity to minute-level to match sub-hour policy boundaries
            time_bucket = datetime.now().strftime("%Y-%m-%d-%H-%M")
            
            # Use SHA-256 hash of JSON serialized fields to prevent cache poisoning
            key_data = json.dumps([device_type, device_id, user_id, source_ip, dest_ip, dest_port, protocol, rule_desc, time_bucket])
            cache_key = hashlib.sha256(key_data.encode('utf-8')).hexdigest()

            if cache_key in self.cache:
                self.cache_hits += 1
                cached_decision = self.cache[cache_key]
                logger.info("cache_hit", alert_id=alert.id, cache_key=cache_key)
                # Clone cached decision with new alert ID and timestamp
                return AccessDecision(
                    action=cached_decision.action,
                    confidence=cached_decision.confidence,
                    reason=f"[CACHED] {cached_decision.reason}",
                    policy_matched=cached_decision.policy_matched,
                    context_analysis=cached_decision.context_analysis,
                    timestamp=datetime.now(timezone.utc)
                )
            self.cache_misses += 1
            # --- END CACHE LOOKUP ---
            
            # Step 1: Context Analysis
            if self.use_single_agent:
                # Single-agent mode: bypass Context Agent and derive risk from rule level
                # Map rule level (0-15) to risk score (0.0-1.0)
                rule_level = alert.rule.level or 5
                risk_score = min(1.0, rule_level / 15.0)
                
                context_analysis = {
                    "risk_score": risk_score,
                    "anomalies_detected": [],
                    "context_summary": f"Single-Agent Mode: Raw alert evaluated directly by Policy Agent. Risk derived from rule level {rule_level}."
                }
            else:
                try:
                    context_analysis = await self._analyze_context(alert)
                except Exception as e:
                    logger.error("context_agent_failed", error=str(e))
                    logger.error("failing_secure_on_context_agent_error")
                    return AccessDecision(
                        action="DENY",
                        confidence=1.0,
                        reason=f"Context Agent failed (fail-secure): {str(e)}",
                        policy_matched="fail_secure_fallback",
                        timestamp=datetime.now(timezone.utc)
                    )

            # Inject deterministic pre-check outcomes into context_summary for Policy Agent
            original_summary = context_analysis.get('context_summary', '')
            precheck_info = (
                f"\n\nDeterministic Pre-checks:\n"
                f"- Deterministic Time check: {time_check_status}\n"
                f"- Deterministic Network check: {network_check_status}"
            )
            context_analysis['context_summary'] = original_summary + precheck_info
            
            # Step 2: Policy Decision (with context as input)
            try:
                policy_decision = await self._evaluate_policy(alert, context_analysis)
            except Exception as e:
                logger.error("policy_agent_failed", error=str(e))
                logger.error("failing_secure_on_policy_agent_error")
                return AccessDecision(
                    action="DENY",
                    confidence=1.0,
                    reason=f"Policy Agent failed (fail-secure): {str(e)}",
                    policy_matched="fail_secure_fallback",
                    timestamp=datetime.now(timezone.utc)
                )
            
            
            # Step 3: Combine results into AccessDecision
            decision = AccessDecision(
                action=policy_decision["action"],
                confidence=policy_decision["confidence"],
                reason=policy_decision["reason"],
                policy_matched=policy_decision.get("policy_matched"),
                context_analysis=context_analysis,
                timestamp=datetime.now(timezone.utc)
            )

            # Store in cache
            self.cache[cache_key] = decision
            
            logger.info(
                "decision_made",
                alert_id=alert.id,
                action=decision.action,
                confidence=decision.confidence
            )
            
            return decision
            
        except Exception as e:
            logger.error("decision_failed", alert_id=alert.id, error=str(e))
            # Fail-safe: DENY on internal pipeline failure to ensure fail-secure enforcement
            return AccessDecision(
                action="DENY",
                confidence=1.0,
                reason=f"Decision pipeline error: {str(e)}",
                policy_matched="error_fallback",
                timestamp=datetime.now(timezone.utc)
            )
    
    @retry(
        stop=stop_after_attempt(2),
        wait=wait_exponential(multiplier=1, min=1, max=5),
        retry=retry_if_exception_type((RateLimitError, APIConnectionError, APITimeoutError, asyncio.TimeoutError))
    )
    async def _analyze_context(self, alert: IoTAccessAlert) -> Dict[str, Any]:
        """
        Use Context Agent to analyze connection context
        
        Args:
            alert: IoT access alert
        
        Returns:
            Context analysis dictionary
        """
        context_prompt = self.prompts["context"].format(
            device_type=alert.device_type or 'Unknown',
            device_id=alert.device_id or 'Unknown',
            source_ip=alert.source_ip or 'Unknown',
            destination_ip=alert.destination_ip,
            destination_port=alert.destination_port,
            protocol=alert.protocol or 'Unknown',
            timestamp=alert.timestamp,
            current_time=datetime.now().isoformat(),
            rule_description=sanitize_secrets(alert.rule.description),
            rule_level=alert.rule.level
        )
        
        # Call context agent with timeout budget
        timeout = self.settings.llm_api_timeout
        result = await asyncio.wait_for(
            call_context_agent(self.llm_client, self.model, context_prompt, self.provider),
            timeout=timeout
        )
        
        # Parse JSON response
        try:
            context_data = self._extract_json(result)
        except (json.JSONDecodeError, ValueError) as e:
            logger.error("context_agent_json_error", error=str(e), response=repr(result))
            context_data = {"risk_score": 0.5, "anomalies_detected": [], "context_summary": "JSON parse error"}
        
        return context_data
    
    @retry(
        stop=stop_after_attempt(2),
        wait=wait_exponential(multiplier=1, min=1, max=5),
        retry=retry_if_exception_type((RateLimitError, APIConnectionError, APITimeoutError, asyncio.TimeoutError))
    )
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
        
        policy_prompt = self.prompts["policy"].format(
            device_type=alert.device_type or 'Unknown',
            device_id=alert.device_id or 'Unknown',
            source_ip=alert.source_ip or 'Unknown',
            timestamp=alert.timestamp,
            user_id=alert.user_id or 'Missing',
            auth_token=alert.auth_token or 'Missing',
            user_role=alert.user_role or 'Unknown',
            session_id=alert.session_id or 'N/A',
            risk_score=context.get('risk_score', 0.5),
            anomalies=context.get('anomalies_detected', []),
            context_summary=sanitize_secrets(context.get('context_summary', 'No context')),
            policies=policies_text
        )
        
        # Call policy agent with timeout budget
        timeout = self.settings.llm_api_timeout
        result = await asyncio.wait_for(
            call_policy_agent(self.llm_client, self.model, policy_prompt, self.provider),
            timeout=timeout
        )
        
        # Parse JSON response
        try:
            policy_data = self._extract_json(result)
        except (json.JSONDecodeError, ValueError) as e:
            logger.error("policy_agent_json_error", error=str(e), response=repr(result))
            policy_data = {"action": "DENY", "confidence": 1.0, "reason": "JSON parse error - fail safe", "policy_matched": "error"}
        
        return policy_data
    
    def _validate_user_authorization(self, alert: IoTAccessAlert):
        """
        Validate user authorization using deterministic code (M0801).
        
        This is a security-critical check that runs BEFORE the LLM.
        It ensures user identification and verification are enforced
        through deterministic, auditable Python logic.
        
        Args:
            alert: IoT access alert
        
        Returns:
            UserAuthResult with authorization decision
        """
        validator = get_user_auth_validator()
        return validator.validate_user_authorization(
            user_id=alert.user_id,
            auth_token=alert.auth_token,
            device_id=alert.device_id,
            device_type=alert.device_type,
            user_role=alert.user_role
        )

    def _extract_json(self, text: str) -> Dict[str, Any]:
        """
        Robustly extract a JSON object from LLM response text.
        Handles: raw JSON, markdown code fences (```json...```), extra preamble text.
        Raises json.JSONDecodeError or ValueError if no valid JSON found.
        """
        import re
        response_text = text if isinstance(text, str) else str(text)
        
        # 1. Strip markdown code fences: ```json\n{...}\n``` or ```\n{...}\n```
        fence_match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', response_text, re.DOTALL)
        if fence_match:
            return json.loads(fence_match.group(1))
        
        # 2. Find the outermost JSON object by scanning for matching braces
        start = response_text.find("{")
        if start == -1:
            raise ValueError(f"No JSON object found in response: {repr(response_text[:200])}")
        
        depth = 0
        end = -1
        in_string = False
        escape_next = False
        for i, ch in enumerate(response_text[start:], start=start):
            if escape_next:
                escape_next = False
                continue
            if ch == '\\' and in_string:
                escape_next = True
                continue
            if ch == '"':
                in_string = not in_string
                continue
            if not in_string:
                if ch == '{':
                    depth += 1
                elif ch == '}':
                    depth -= 1
                    if depth == 0:
                        end = i + 1
                        break
        
        if end == -1:
            raise ValueError(f"Unbalanced braces in response: {repr(response_text[:200])}")
        
        return json.loads(response_text[start:end])

    def _get_policy(self, device_type: str) -> Optional[Dict[str, Any]]:
        """Find policy for device type in config policies list"""
        for policy in self.policies.get('policies', []):
            if policy.get('device_type') == device_type:
                return policy
        return None

    def _check_time_policy(self, timestamp: str, allowed_hours: str, allowed_days: Optional[List[str]] = None) -> Tuple[bool, str]:
        """Check if timestamp falls within allowed hours and days"""
        try:
            # Parse timestamp supporting both Z and timezone offsets
            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            
            # Check day of week if specified
            if allowed_days:
                day_name = dt.strftime('%A')
                if day_name not in allowed_days:
                    return False, f"Outside allowed days (day: {day_name}, allowed: {allowed_days})"
            
            # Check hour/minutes if allowed_hours is specified
            if allowed_hours:
                start_str, end_str = allowed_hours.split('-')
                start_hour, start_min = map(int, start_str.split(':'))
                end_hour, end_min = map(int, end_str.split(':'))
                
                current_minutes = dt.hour * 60 + dt.minute
                start_minutes = start_hour * 60 + start_min
                end_minutes = end_hour * 60 + end_min
                
                if not (start_minutes <= current_minutes < end_minutes):
                    return False, f"Outside allowed hours (time: {dt.strftime('%H:%M')}, allowed: {allowed_hours})"
            
            return True, "PASS"
        except Exception as e:
            logger.error("time_policy_check_parse_failed", timestamp=timestamp, error=str(e))
            # Fail-secure: DENY on parsing errors to prevent potential bypasses
            return False, f"Time parsing error (fail-secure): {str(e)}"

    def _check_network_policy(self, source_ip: str, allowed_source_networks: List[str]) -> Tuple[bool, str]:
        """Check if source IP is in allowed networks (using standard ipaddress CIDR matching)"""
        if not source_ip:
            return False, "Source IP is missing"
            
        try:
            ip_obj = ipaddress.ip_address(source_ip)
        except ValueError:
            return False, f"Invalid source IP address format: {source_ip}"
            
        for network_str in allowed_source_networks:
            try:
                # Parse as network
                net_obj = ipaddress.ip_network(network_str, strict=False)
                if ip_obj in net_obj:
                    return True, "PASS"
            except ValueError:
                # If it's not a valid network, maybe it's a raw IP
                if source_ip == network_str:
                    return True, "PASS"
                    
        return False, f"Source IP {source_ip} not in allowed networks {allowed_source_networks}"

    def _is_rate_limited(self, source_ip: str) -> bool:
        """
        Check if a source IP has exceeded the LLM invocation rate limit.
        
        Uses a sliding window approach: tracks timestamps of recent LLM
        invocations per IP, and rejects new requests if the count within
        the window exceeds the configured maximum.
        
        This is a DoS mitigation mechanism to prevent attackers from
        exhausting the LLM API budget by flooding with syntactically
        valid requests that bypass Layer 0.
        
        Args:
            source_ip: The source IP address to check
            
        Returns:
            True if the IP is rate-limited (should be denied)
        """
        now = time.monotonic()
        window_start = now - self.rate_limit_window_s
        
        # Prune expired entries
        timestamps = self._rate_limit_tracker[source_ip]
        self._rate_limit_tracker[source_ip] = [t for t in timestamps if t > window_start]
        
        # Check if limit exceeded
        if len(self._rate_limit_tracker[source_ip]) >= self.rate_limit_max_requests:
            return True
        
        # Record this invocation
        self._rate_limit_tracker[source_ip].append(now)
        return False

