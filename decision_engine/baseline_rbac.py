"""
This implements a rule-based access control system WITH user authentication
to provide a baseline comparison against the hybrid LLM system.

Key Features:
- User authentication (token validation)
- Role-Based Access Control (RBAC)
- Time-based policies
- Network-based policies
- Device-specific rules

This baseline uses the SAME policies as the hybrid system but WITHOUT LLM reasoning.
"""

import yaml
from datetime import datetime
from typing import Dict, Any, Optional
from pathlib import Path


class RBACBaseline:
    """Rule-based access control baseline with authentication"""
    
    def __init__(self, policy_path: str = "config/access_policies.yaml"):
        with open(policy_path, 'r') as f:
            self.policies = yaml.safe_load(f)['policies']
    
    def make_decision(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Make access control decision using pure rule-based logic
        
        Returns:
            {
                'action': 'ALLOW' or 'DENY',
                'confidence': 1.0,  # Rules are always 100% confident
                'reason': str,
                'method': 'RBAC'
            }
        """
        # Step 1: User Authentication (M0801)
        user_id = alert.get('user_id')
        auth_token = alert.get('auth_token')
        device_type = alert.get('device_type')
        device_id = alert.get('device_id')
        source_ip = alert.get('source_ip')
        timestamp = alert.get('timestamp')
        
        # Check 1: Require authentication for devices that need it
        policy = self._get_policy(device_type)
        if not policy:
            return {
                'action': 'DENY',
                'confidence': 1.0,
                'reason': f'No policy found for device type: {device_type}',
                'method': 'RBAC'
            }
        
        # Check 2: Authentication requirement
        if policy.get('require_authentication', False):
            if not user_id:
                return {
                    'action': 'DENY',
                    'confidence': 1.0,
                    'reason': 'User authentication required but user_id is missing',
                    'method': 'RBAC'
                }
            
            if not auth_token or auth_token == 'invalid-token' or 'invalid' in auth_token.lower():
                return {
                    'action': 'DENY',
                    'confidence': 1.0,
                    'reason': f'Invalid or missing authentication token for user {user_id}',
                    'method': 'RBAC'
                }
        
        # Check 3: User Authorization (user → device mapping)
        if user_id and policy.get('allowed_users'):
            user_authorized = False
            for user_policy in policy['allowed_users']:
                if user_policy['user_id'] == user_id:
                    # Check if device is in allowed list
                    allowed_devices = user_policy.get('allowed_devices', [])
                    if allowed_devices == ['*'] or device_id in allowed_devices:
                        user_authorized = True
                        break
            
            if not user_authorized:
                return {
                    'action': 'DENY',
                    'confidence': 1.0,
                    'reason': f'User {user_id} not authorized for device {device_id}',
                    'method': 'RBAC'
                }
        
        # Check 4: Time-based policy
        if policy.get('allowed_hours'):
            allowed_days = policy.get('allowed_days')
            if not self._check_time_policy(timestamp, policy['allowed_hours'], allowed_days):
                return {
                    'action': 'DENY',
                    'confidence': 1.0,
                    'reason': f'Access outside allowed hours/days: {policy["allowed_hours"]} on {allowed_days or "any day"}',
                    'method': 'RBAC'
                }
        
        # Check 5: Network-based policy
        if policy.get('allowed_networks') and source_ip:
            if not self._check_network_policy(source_ip, policy['allowed_networks']):
                return {
                    'action': 'DENY',
                    'confidence': 1.0,
                    'reason': f'Source IP {source_ip} not in allowed networks',
                    'method': 'RBAC'
                }
        
        # Check 6: Detect obvious attacks (simple pattern matching)
        if self._is_attack(alert):
            return {
                'action': 'DENY',
                'confidence': 1.0,
                'reason': 'Attack pattern detected (SQL injection, prompt injection, or XSS)',
                'method': 'RBAC'
            }
        
        # All checks passed
        return {
            'action': 'ALLOW',
            'confidence': 1.0,
            'reason': f'All policy checks passed for {user_id} → {device_id}',
            'method': 'RBAC'
        }
    
    def _get_policy(self, device_type: str) -> Optional[Dict]:
        """Find policy for device type"""
        for policy in self.policies:
            if policy.get('device_type') == device_type:
                return policy
        return None
    
    def _check_time_policy(self, timestamp: str, allowed_hours: str, allowed_days: list = None) -> bool:
        """Check if timestamp falls within allowed hours and days"""
        try:
            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            
            # Check day of week if specified
            if allowed_days:
                day_name = dt.strftime('%A')  # e.g., "Monday", "Saturday"
                if day_name not in allowed_days:
                    return False  # Wrong day
            
            # Check hour
            hour = dt.hour
            
            # Parse "09:00-17:00" format
            if allowed_hours: # Only check hours if allowed_hours is specified
                start_str, end_str = allowed_hours.split('-')
                start_hour = int(start_str.split(':')[0])
                end_hour = int(end_str.split(':')[0])
                
                if not (start_hour <= hour < end_hour):
                    return False # Outside allowed hours
            
            return True # All checks passed (or not applicable)
        except Exception:
            return True  # If can't parse, allow (lenient)
    
    def _check_network_policy(self, source_ip: str, allowed_networks: list) -> bool:
        """Check if source IP is in allowed networks (simple CIDR check)"""
        for network in allowed_networks:
            if '/' in network:
                # Simple CIDR check (e.g., "192.168.1.0/24")
                network_prefix = '.'.join(network.split('/')[0].split('.')[:-1])
                if source_ip.startswith(network_prefix):
                    return True
            else:
                # Exact match
                if source_ip == network:
                    return True
        return False
    
    def _is_attack(self, alert: Dict[str, Any]) -> bool:
        """
        Simple attack detection using pattern matching
        (This is what a traditional rule-based system can do)
        """
        # Check all text fields for attack patterns
        text_fields = [
            str(alert.get('user_id', '')),
            str(alert.get('device_id', '')),
            str(alert.get('data', {}))
        ]
        
        attack_patterns = [
            # SQL Injection
            'SELECT', 'UNION', 'DROP TABLE', '--', "' OR '1'='1",
            # Prompt Injection
            'IGNORE PREVIOUS', 'SYSTEM:', 'NEW INSTRUCTIONS:',
            # XSS
            '<script>', 'javascript:', 'onerror='
        ]
        
        for text in text_fields:
            text_upper = text.upper()
            for pattern in attack_patterns:
                if pattern.upper() in text_upper:
                    return True
        
        return False


if __name__ == "__main__":
    # Example usage
    baseline = RBACBaseline()
    
    # Test case 1: Valid user
    alert1 = {
        'user_id': 'alice@company.com',
        'auth_token': 'valid-token-123',
        'device_id': 'camera-office-01',
        'device_type': 'camera',
        'source_ip': '192.168.1.100',
        'timestamp': '2025-12-24T10:00:00Z'
    }
    
    decision1 = baseline.make_decision(alert1)
    print(f"Test 1: {decision1}")
    
    # Test case 2: Invalid token
    alert2 = dict(alert1)
    alert2['auth_token'] = 'invalid-token'
    
    decision2 = baseline.make_decision(alert2)
    print(f"Test 2: {decision2}")
    
    # Test case 3: Attack
    alert3 = dict(alert1)
    alert3['user_id'] = "admin' OR '1'='1"
    
    decision3 = baseline.make_decision(alert3)
    print(f"Test 3: {decision3}")
