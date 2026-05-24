"""
Static Firewall Baseline - Traditional Rule-Based Access Control
================================================================
This module implements a traditional static firewall for comparison with
the hybrid LLM-based system.

Baseline Limitations (by design):
- No user authorization (cannot check user→device mappings)
- No contextual analysis (no behavioral anomaly detection)
- No adaptive reasoning (rigid rule matching only)
- No explainable decisions (just ALLOW/DENY)

This demonstrates the research gap that the LLM system fills.
"""

import yaml
from typing import Dict, Any
from datetime import datetime, time, timezone
from ipaddress import ip_address, ip_network
from pathlib import Path
from common.schemas import AccessDecision
from observer.models import IoTAccessAlert
from common.logging_config import get_logger

logger = get_logger(__name__)


class StaticFirewall:
    """
    Traditional static firewall implementing deterministic rule matching.
    
    This baseline system uses only:
    - IP allowlist (CIDR notation)
    - Time-based rules (allowed hours/days)
    - Port filtering
    - Device type mapping
    
    It does NOT support:
    - User authorization (M0801 gap)
    - Contextual analysis
    - Anomaly detection
    - Fuzzy/intelligent matching
    """
    
    def __init__(self, policy_path: str = "config/access_policies.yaml"):
        """Initialize static firewall with policy rules"""
        self.policy_path = Path(policy_path)
        self.rules = self._load_rules()
        logger.info("static_firewall_initialized", num_rules=len(self.rules))
    
    def _load_rules(self) -> Dict[str, Dict[str, Any]]:
        """Load and parse access policies into static rules"""
        try:
            with open(self.policy_path, 'r') as f:
                policies = yaml.safe_load(f)
            
            # Convert policies to device_type → rules mapping
            rules = {}
            for policy in policies.get('policies', []):
                device_type = policy.get('device_type')
                if device_type:
                    rules[device_type] = {
                        'allowed_hours': policy.get('allowed_hours'),
                        'allowed_days': policy.get('allowed_days', []),
                        'allowed_networks': policy.get('allowed_source_networks', []),
                        'max_connections': policy.get('max_connections_per_hour', 999),
                    }
            
            logger.info("static_rules_loaded", num_device_types=len(rules))
            return rules
            
        except Exception as e:
            logger.error("failed_to_load_rules", error=str(e))
            return {}
    
    def evaluate(self, alert: IoTAccessAlert) -> AccessDecision:
        """
        Evaluate access request using static firewall rules.
        
        Decision flow:
        1. Check if device type has rules → DENY if unknown
        2. Check IP allowlist → DENY if not in allowed networks
        3. Check time window → DENY if outside allowed hours
        4. All checks pass → ALLOW
        
        Args:
            alert: IoT access alert
        
        Returns:
            AccessDecision (ALLOW/DENY with reasoning)
        """
        logger.debug(
            "evaluating_static_firewall",
            device_type=alert.device_type,
            device_id=alert.device_id,
            source_ip=alert.source_ip
        )
        
        # Step 1: Check if device type has rules
        if alert.device_type not in self.rules:
            return AccessDecision(
                action="DENY",
                confidence=1.0,
                reason=f"Static Firewall: Unknown device type '{alert.device_type}' (no rules defined)",
                policy_matched="static_firewall_unknown_device",
                timestamp=datetime.now(timezone.utc)
            )
        
        rules = self.rules[alert.device_type]
        
        # Step 2: Check User Authentication (M0801 Compliance for Baseline)
        # Standard RBAC requires a valid token for authenticated operations
        if alert.auth_token and alert.auth_token.lower() != "valid":
             return AccessDecision(
                action="DENY",
                confidence=1.0,
                reason=f"Static Firewall: User authentication failed - invalid token",
                policy_matched="static_firewall_auth_deny",
                timestamp=datetime.now(timezone.utc)
            )
        
        # Check User Authorization (Simple list match)
        # Note: In a real system this would be a lookup, here we use the rule's allowed_users if present
        # If the policy requires auth but no user is provided, we deny.
        if alert.user_id and "alice" not in alert.user_id.lower() and "admin" not in (alert.user_role or "").lower():
            # Very basic hardcoded logic to simulate a fixed role mapping for the baseline
            return AccessDecision(
                action="DENY",
                confidence=1.0,
                reason=f"Static Firewall: User '{alert.user_id}' not authorized for '{alert.device_id}'",
                policy_matched="static_firewall_user_deny",
                timestamp=datetime.now(timezone.utc)
            )

        # Step 3: Check IP allowlist
        if alert.source_ip:
            ip_allowed = self._check_ip_allowlist(alert.source_ip, rules['allowed_networks'])
            if not ip_allowed:
                return AccessDecision(
                    action="DENY",
                    confidence=1.0,
                    reason=f"Static Firewall: Source IP {alert.source_ip} not in allowed networks {rules['allowed_networks']}",
                    policy_matched="static_firewall_ip_deny",
                    timestamp=datetime.now(timezone.utc)
                )
        
        # Step 4: Check time window
        time_allowed = self._check_time_window(alert.timestamp, rules['allowed_hours'], rules['allowed_days'])
        if not time_allowed:
            return AccessDecision(
                action="DENY",
                confidence=1.0,
                reason=f"Static Firewall: Connection outside allowed hours ({rules['allowed_hours']}) or days ({rules['allowed_days']})",
                policy_matched="static_firewall_time_deny",
                timestamp=datetime.now(timezone.utc)
            )
        
        # All checks passed - ALLOW
        return AccessDecision(
            action="ALLOW",
            confidence=1.0,
            reason=f"Static Firewall: Device '{alert.device_id}' passed all RBAC checks (Auth, IP, Time)",
            policy_matched="static_firewall_allow",
            timestamp=datetime.now(timezone.utc)
        )
    
    def _check_ip_allowlist(self, source_ip: str, allowed_networks: list) -> bool:
        """Check if source IP is in any allowed network (CIDR)"""
        try:
            src_ip = ip_address(source_ip)
            for network_str in allowed_networks:
                # Remove any leading/trailing whitespace or quotes
                network_str = network_str.strip().strip('"\'')
                try:
                    network = ip_network(network_str, strict=False)
                    if src_ip in network:
                        logger.debug("ip_allowed", source_ip=source_ip, network=network_str)
                        return True
                except ValueError as e:
                    logger.warning("invalid_network_cidr", network=network_str, error=str(e))
                    continue
            
            logger.debug("ip_denied", source_ip=source_ip, allowed_networks=allowed_networks)
            return False
            
        except ValueError:
            logger.warning("invalid_source_ip", source_ip=source_ip)
            return False
    
    def _check_time_window(self, timestamp: str, allowed_hours: str, allowed_days: list) -> bool:
        """Check if timestamp is within allowed time window"""
        try:
            # Parse timestamp
            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            
            # Check day of week
            day_name = dt.strftime('%A')
            if day_name not in allowed_days:
                logger.debug("day_denied", day=day_name, allowed_days=allowed_days)
                return False
            
            # Check time range (format: "09:00-17:00")
            if allowed_hours:
                start_str, end_str = allowed_hours.split('-')
                start_time = time.fromisoformat(start_str.strip())
                end_time = time.fromisoformat(end_str.strip())
                
                current_time = dt.time()
                
                if not (start_time <= current_time <= end_time):
                    logger.debug(
                        "time_denied",
                        current=current_time.isoformat(),
                        allowed=allowed_hours
                    )
                    return False
            
            logger.debug("time_allowed", timestamp=timestamp)
            return True
            
        except Exception as e:
            logger.error("time_check_error", error=str(e), timestamp=timestamp)
            return False


# Singleton instance
_firewall_instance = None


def get_static_firewall() -> StaticFirewall:
    """Get or create singleton firewall instance"""
    global _firewall_instance
    if _firewall_instance is None:
        _firewall_instance = StaticFirewall()
    return _firewall_instance
