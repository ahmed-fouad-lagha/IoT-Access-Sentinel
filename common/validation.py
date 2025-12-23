"""
Input Validation and Sanitization for IoT-Access-Sentinel
Security-critical input handling before LLM processing

Protects against:
- Prompt injection attacks
- SQL injection patterns
- XSS and code injection
- Malformed/malicious device IDs
"""

import re
import logging
from typing import Optional, Tuple, List

logger = logging.getLogger(__name__)


# Patterns for valid field values
VALID_DEVICE_ID = re.compile(r'^[a-zA-Z0-9\-\_\.]{1,64}$')
VALID_USER_ID = re.compile(r'^[a-zA-Z0-9\-\_\.@]{1,64}$')
VALID_DEVICE_TYPE = re.compile(r'^[a-zA-Z0-9\-\_\s]{1,32}$')
VALID_IP_ADDRESS = re.compile(
    r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
    r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
)

# Dangerous patterns to detect
INJECTION_PATTERNS = [
    # SQL injection
    (re.compile(r"(?i)(union\s+select|drop\s+table|insert\s+into|delete\s+from)", re.IGNORECASE), "sql_injection"),
    (re.compile(r"['\";]--"), "sql_comment"),
    (re.compile(r"(?i)(\bor\b|\band\b)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+"), "sql_tautology"),
    
    # LLM prompt injection
    (re.compile(r"(?i)(ignore|forget|disregard)\s+(all\s+)?(previous|prior|above)", re.IGNORECASE), "prompt_injection"),
    (re.compile(r"(?i)system\s*:\s*", re.IGNORECASE), "system_prompt_override"),
    (re.compile(r"(?i)(you\s+are|act\s+as|pretend\s+to\s+be)", re.IGNORECASE), "role_hijack"),
    (re.compile(r"(?i)allow\s+(all|this|access)", re.IGNORECASE), "manipulation_attempt"),
    
    # Code injection
    (re.compile(r"<script|javascript:|on\w+\s*=", re.IGNORECASE), "xss"),
    (re.compile(r"\$\{|\$\(|`.*`", re.IGNORECASE), "command_injection"),
    
    # Unicode attacks
    (re.compile(r"[\u202E\u200F\u200E]"), "unicode_rtlo"),  # Right-to-left override
    (re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F]"), "null_bytes"),  # Control characters
]


class ValidationResult:
    """Result of input validation."""
    
    def __init__(self, is_valid: bool, field: str = None, error: str = None, threat_type: str = None):
        self.is_valid = is_valid
        self.field = field
        self.error = error
        self.threat_type = threat_type
    
    def __bool__(self):
        return self.is_valid
    
    def __repr__(self):
        if self.is_valid:
            return "ValidationResult(valid=True)"
        return f"ValidationResult(valid=False, field={self.field}, error={self.error})"


class InputValidator:
    """Validates and sanitizes input before LLM processing."""
    
    def __init__(self, strict_mode: bool = True):
        """
        Args:
            strict_mode: If True, reject on any suspicious pattern.
                        If False, sanitize and continue.
        """
        self.strict_mode = strict_mode
        self.threat_log: List[dict] = []
    
    def validate_device_id(self, device_id: Optional[str]) -> ValidationResult:
        """Validate device_id field."""
        if device_id is None:
            return ValidationResult(True)  # Optional field
        
        # Check for injection patterns first
        threat = self._detect_injection(device_id)
        if threat:
            self._log_threat("device_id", device_id, threat)
            return ValidationResult(False, "device_id", f"Injection detected: {threat}", threat)
        
        # Check format
        if not VALID_DEVICE_ID.match(device_id):
            return ValidationResult(False, "device_id", "Invalid device_id format")
        
        return ValidationResult(True)
    
    def validate_user_id(self, user_id: Optional[str]) -> ValidationResult:
        """Validate user_id field."""
        if user_id is None:
            return ValidationResult(True)
        
        threat = self._detect_injection(user_id)
        if threat:
            self._log_threat("user_id", user_id, threat)
            return ValidationResult(False, "user_id", f"Injection detected: {threat}", threat)
        
        if not VALID_USER_ID.match(user_id):
            return ValidationResult(False, "user_id", "Invalid user_id format")
        
        return ValidationResult(True)
    
    def validate_device_type(self, device_type: Optional[str]) -> ValidationResult:
        """Validate device_type field."""
        if device_type is None:
            return ValidationResult(True)
        
        threat = self._detect_injection(device_type)
        if threat:
            self._log_threat("device_type", device_type, threat)
            return ValidationResult(False, "device_type", f"Injection detected: {threat}", threat)
        
        if not VALID_DEVICE_TYPE.match(device_type):
            return ValidationResult(False, "device_type", "Invalid device_type format")
        
        return ValidationResult(True)
    
    def validate_source_ip(self, source_ip: Optional[str]) -> ValidationResult:
        """Validate source_ip field."""
        if source_ip is None:
            return ValidationResult(True)
        
        if not VALID_IP_ADDRESS.match(source_ip):
            return ValidationResult(False, "source_ip", "Invalid IP address format")
        
        return ValidationResult(True)
    
    def validate_all(self, alert_data: dict) -> ValidationResult:
        """
        Validate all fields in an alert.
        
        Returns first validation failure, or success if all pass.
        """
        validations = [
            self.validate_device_id(alert_data.get("device_id")),
            self.validate_user_id(alert_data.get("user_id")),
            self.validate_device_type(alert_data.get("device_type")),
            self.validate_source_ip(alert_data.get("source_ip")),
        ]
        
        for result in validations:
            if not result.is_valid:
                return result
        
        return ValidationResult(True)
    
    def sanitize(self, text: str) -> str:
        """
        Sanitize text by removing dangerous patterns.
        
        Use only if strict_mode=False and you want to proceed with sanitized input.
        """
        if not text:
            return text
        
        # Remove control characters
        sanitized = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\u202E\u200F\u200E]', '', text)
        
        # Escape special characters
        sanitized = sanitized.replace('<', '&lt;').replace('>', '&gt;')
        
        # Remove SQL comments
        sanitized = re.sub(r'--.*$', '', sanitized, flags=re.MULTILINE)
        
        # Truncate to reasonable length
        return sanitized[:256]
    
    def _detect_injection(self, text: str) -> Optional[str]:
        """Detect injection patterns in text."""
        if not text:
            return None
        
        for pattern, threat_type in INJECTION_PATTERNS:
            if pattern.search(text):
                return threat_type
        
        return None
    
    def _log_threat(self, field: str, value: str, threat_type: str):
        """Log detected threat for analysis."""
        entry = {
            "field": field,
            "value": value[:100],  # Truncate for safety
            "threat_type": threat_type,
            "timestamp": __import__("datetime").datetime.now().isoformat()
        }
        self.threat_log.append(entry)
        logger.warning(f"Threat detected: {threat_type} in {field}")
    
    def get_threat_summary(self) -> dict:
        """Get summary of detected threats."""
        if not self.threat_log:
            return {"total_threats": 0}
        
        by_type = {}
        for entry in self.threat_log:
            t = entry["threat_type"]
            by_type[t] = by_type.get(t, 0) + 1
        
        return {
            "total_threats": len(self.threat_log),
            "by_type": by_type,
            "recent": self.threat_log[-5:]
        }


# Global validator instance
validator = InputValidator(strict_mode=True)


def validate_alert(alert_data: dict) -> ValidationResult:
    """Convenience function to validate alert data."""
    return validator.validate_all(alert_data)
