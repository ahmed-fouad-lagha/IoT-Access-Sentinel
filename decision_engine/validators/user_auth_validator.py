"""
User Authorization Validator - M0801 Implementation
====================================================
This module provides deterministic, code-based user authorization validation
to ensure reliable user identification and verification for IoT access control.

This is part of the hybrid architecture:
- User authorization: Validated by deterministic Python code (THIS MODULE)
- Contextual analysis: Handled by LLM (Policy Agent)

Design rationale:
- User authorization is a security-critical decision that should not rely on 
  probabilistic LLM inference
- Deterministic validation ensures 100% accuracy for user-device mappings
- Explicit Python code is auditable and transparent for security compliance
"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass
import yaml
from pathlib import Path
import jwt
from config.settings import get_settings
from common.logging_config import get_logger

logger = get_logger(__name__)


@dataclass
class UserAuthResult:
    """Result of user authorization validation"""
    authorized: bool
    reason: str
    matched_user: Optional[str] = None
    matched_devices: Optional[List[str]] = None
    matched_role: Optional[str] = None
    token_status: Optional[str] = None


class UserAuthValidator:
    """
    Validates user authorization for IoT device access.
    
    This validator performs deterministic checks for:
    1. User identification (user_id present and valid)
    2. Authentication token validation (if required)
    3. User-to-device authorization (user allowed to access device)
    4. Role-based access control
    """
    
    def __init__(self, policy_path: str = "config/access_policies.yaml"):
        """Initialize validator with policy configuration"""
        self.policy_path = Path(policy_path)
        self.policies = self._load_policies()
        logger.info("user_auth_validator_initialized", policy_path=str(self.policy_path))
    
    def _load_policies(self) -> Dict[str, Any]:
        """Load access policies from YAML file"""
        try:
            with open(self.policy_path, 'r') as f:
                policies = yaml.safe_load(f)
            logger.debug("policies_loaded", num_device_types=len(policies.get('device_types', {})))
            return policies
        except Exception as e:
            logger.error("failed_to_load_policies", error=str(e), path=str(self.policy_path))
            raise
    
    def validate_user_authorization(
        self,
        user_id: Optional[str],
        auth_token: Optional[str],
        device_id: str,
        device_type: str,
        user_role: Optional[str] = None
    ) -> UserAuthResult:
        """
        Validate user authorization for device access.
        
        Args:
            user_id: User identifier (e.g., email)
            auth_token: Authentication token
            device_id: Device identifier being accessed
            device_type: Type of device (camera, sensor, smart_lock)
            user_role: User role (admin, user, guest)
        
        Returns:
            UserAuthResult with authorization decision and reasoning
        """
        logger.debug(
            "validating_user_authorization",
            user_id=user_id,
            device_id=device_id,
            device_type=device_type,
            user_role=user_role
        )
        
        # Get device-specific policy
        device_policy = self._get_device_policy(device_type)
        if not device_policy:
            return UserAuthResult(
                authorized=False,
                reason=f"No policy found for device type: {device_type}"
            )
        
        # Check if authentication is required
        requires_auth = device_policy.get('require_authentication', False)
        
        if not requires_auth:
            # No user authorization required for this device type
            logger.debug("device_type_does_not_require_auth", device_type=device_type)
            # Try to find a role in the policy if user_id is provided
            matched_role = None
            if user_id:
                allowed_users = device_policy.get('allowed_users', [])
                user_match = self._find_user_in_policy(user_id, allowed_users)
                if user_match:
                    matched_role = user_match.get('role')
            return UserAuthResult(
                authorized=True,
                reason=f"Device type '{device_type}' does not require user authentication",
                token_status="NOT_REQUIRED",
                matched_role=matched_role or "system"
            )
        
        # Authentication required - validate user
        if not user_id:
            return UserAuthResult(
                authorized=False,
                reason="User authentication required but user_id is missing",
                token_status="MISSING"
            )
        
        # Validate authentication token
        token_payload = self._validate_auth_token(auth_token, device_policy, user_id)
        if not token_payload:
            return UserAuthResult(
                authorized=False,
                reason="Invalid or missing authentication token",
                token_status="INVALID"
            )
        
        # Check user-to-device authorization
        allowed_users = device_policy.get('allowed_users', [])
        user_match = self._find_user_in_policy(user_id, allowed_users)
        
        if not user_match:
            return UserAuthResult(
                authorized=False,
                reason=f"User '{user_id}' not in allowed_users list for {device_type}",
                token_status="VALID"
            )
        
        # Determine user role (prefer policy, fallback to token)
        matched_role = user_match.get('role') or token_payload.get('role')
        
        # Check if user is authorized for this specific device
        user_allowed_devices = user_match.get('allowed_devices', [])
        
        # Support wildcard access for system accounts
        if "*" in user_allowed_devices:
            logger.info(
                "wildcard_access_granted",
                user_id=user_id,
                device_id=device_id,
                device_type=device_type
            )
            return UserAuthResult(
                authorized=True,
                reason=f"User '{user_id}' has wildcard access to all {device_type} devices",
                matched_user=user_id,
                matched_devices=["*"],
                matched_role=matched_role,
                token_status="VALID"
            )
        
        if device_id not in user_allowed_devices:
            return UserAuthResult(
                authorized=False,
                reason=f"User '{user_id}' not authorized for device '{device_id}'. Allowed devices: {user_allowed_devices}",
                matched_user=user_id,
                matched_devices=user_allowed_devices,
                matched_role=matched_role,
                token_status="VALID"
            )
        
        # All checks passed
        logger.info(
            "user_authorization_granted",
            user_id=user_id,
            device_id=device_id,
            device_type=device_type
        )
        return UserAuthResult(
            authorized=True,
            reason=f"User '{user_id}' authorized for device '{device_id}'",
            matched_user=user_id,
            matched_devices=user_allowed_devices,
            matched_role=matched_role,
            token_status="VALID"
        )
    
    def _get_device_policy(self, device_type: str) -> Optional[Dict[str, Any]]:
        """Get policy for specific device type"""
        policies = self.policies.get('policies', [])
        logger.debug(f"Looking for device_type '{device_type}' in {len(policies)} policies")
        for policy in policies:
            policy_device_type = policy.get('device_type')
            logger.debug(f"Checking policy with device_type='{policy_device_type}'")
            if policy_device_type == device_type:
                logger.debug(f"Found matching policy for '{device_type}'")
                return policy
        logger.warning(f"No policy found for device_type '{device_type}'")
        return None
    
    def _validate_auth_token(self, auth_token: Optional[str], device_policy: Dict[str, Any], expected_user_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        Validate authentication token.
        
        Verifies the JWT signature and expiration. Returns the decoded payload if valid.
        """
        if not auth_token:
            return None
            
        try:
            settings = get_settings()
            # Decode and verify the JWT
            verify_exp = getattr(settings, "verify_jwt_expiration", True)
            decoded = jwt.decode(
                auth_token, 
                settings.jwt_secret_key, 
                algorithms=[settings.jwt_algorithm],
                options={"verify_signature": True, "verify_exp": verify_exp}
            )
            
            # Verify subject matches user_id if expected_user_id is provided
            if expected_user_id and decoded.get("sub") != expected_user_id:
                logger.warning("jwt_subject_mismatch", sub=decoded.get("sub"), expected=expected_user_id)
                return None
                
            return decoded
        except jwt.ExpiredSignatureError:
            logger.warning("jwt_token_expired")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning("jwt_token_invalid", error=str(e))
            return None
    
    def _find_user_in_policy(self, user_id: str, allowed_users: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Find user in allowed_users list"""
        for user in allowed_users:
            if user.get('user_id') == user_id:
                return user
        return None


# Singleton instance for easy import
_validator_instance: Optional[UserAuthValidator] = None


def get_user_auth_validator() -> UserAuthValidator:
    """Get or create singleton validator instance"""
    global _validator_instance
    if _validator_instance is None:
        _validator_instance = UserAuthValidator()
    return _validator_instance
