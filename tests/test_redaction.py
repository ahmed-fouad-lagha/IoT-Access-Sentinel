import pytest
from common.validation import sanitize_secrets

def test_sanitize_secrets_basic():
    """Test redaction of standard password and API key formats"""
    text = "Connecting with password=mypassword123 and api_key: AIzaSyB-1234567890"
    sanitized = sanitize_secrets(text)
    assert "mypassword123" not in sanitized
    assert "AIzaSyB-1234567890" not in sanitized
    assert "password=***REDACTED***" in sanitized
    assert "api_key: ***REDACTED***" in sanitized

def test_sanitize_secrets_auth_header():
    """Test redaction of Authorization headers and Bearer tokens"""
    text = "Header Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIi... and X-API-Key ABC123DEF456"
    sanitized = sanitize_secrets(text)
    assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in sanitized
    assert "ABC123DEF456" not in sanitized
    assert "Bearer ***REDACTED***" in sanitized
    assert "X-API-Key ***REDACTED***" in sanitized

def test_sanitize_secrets_proprietary_tokens():
    """Test redaction of custom/proprietary token formats identified in review"""
    # Test with quotes and different separators
    text = 'Setting token: "custom-prop-token-xyz-987654321"'
    sanitized = sanitize_secrets(text)
    assert "custom-prop-token-xyz-987654321" not in sanitized
    assert 'token: "***REDACTED***"' in sanitized
    
    # Test with assignment and brackets
    text = "auth_token=[SECRET_1234567890]"
    sanitized = sanitize_secrets(text)
    assert "SECRET_1234567890" not in sanitized
    assert "auth_token=[***REDACTED***]" in sanitized

def test_sanitize_secrets_high_entropy():
    """Test redaction of long high-entropy strings that look like secrets"""
    # Long hex string (e.g., hash or session ID)
    text = "SessionID is 5f352379324c084042898950d8763523 and hash is a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"
    sanitized = sanitize_secrets(text)
    assert "5f352379324c084042898950d8763523" not in sanitized
    assert "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3" not in sanitized
    assert "***REDACTED_HASH***" in sanitized

    # Long base64-like string (using non-keyword prefix to test generic redaction)
    text = "The raw payload is R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7"
    sanitized = sanitize_secrets(text)
    assert "R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7" not in sanitized
    assert "***REDACTED_SECRET***" in sanitized

def test_sanitize_secrets_jwt():
    """Test redaction of JWT-like structures"""
    jwt_text = "jwt: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    sanitized = sanitize_secrets(jwt_text)
    assert "eyJhbGci" not in sanitized
    assert "***REDACTED_JWT***" in sanitized
