"""
Configuration - IoT-Access-Sentinel
Environment-based configuration adapted from AI_SOC pattern

Manages settings for:
- Wazuh Manager connection
- LLM API configuration
- Enforcement policies
- Service endpoints
"""

from pydantic_settings import BaseSettings, SettingsConfigDict
from functools import lru_cache
from typing import Optional


class Settings(BaseSettings):
    """Application settings loaded from environment variables"""

    # Service Identity
    service_name: str = "iot-access-sentinel"
    service_version: str = "0.1.0"
    
    # Wazuh Manager Configuration (adapted from AI_SOC)
    wazuh_manager_url: str = "https://wazuh-manager:55000"
    wazuh_username: str = "wazuh-wui"
    wazuh_password: str  # Required - loaded from .env
    wazuh_verify_ssl: bool = False  # Set True in production with valid certs
    
    # Wazuh Alert Filtering
    min_severity: int = 5  # IoT access events typically lower than intrusions
    max_alerts_per_request: int = 100
    
    # LLM Configuration (OpenAI/Gemini/Ollama)
    llm_provider: str = "openai"  # Options: "openai", "gemini", "ollama"
    openai_api_key: Optional[str] = None
    openai_base_url: Optional[str] = None  # For Groq or other OpenAI-compatible APIs
    gemini_api_key: Optional[str] = None
    ollama_base_url: Optional[str] = "http://localhost:11434"
    
    llm_model: str = "gpt-4"  # Default model
    llm_temperature: float = 0.1  # Low temperature for deterministic decisions
    llm_max_tokens: int = 512
    
    # Access Policy Configuration
    policy_file_path: str = "config/access_policies.yaml"
    
    # Enforcement Configuration
    enforcement_enabled: bool = True  # Set False for dry-run mode
    enforcement_timeout: int = 10  # Seconds
    
    # API Configuration
    host: str = "0.0.0.0"
    port: int = 8000
    log_level: str = "info"
    
    # JWT and Webhook Secrets
    jwt_secret_key: str  # Required - loaded from .env
    jwt_algorithm: str = "HS256"
    webhook_api_key: str  # Required - loaded from .env
    
    # Timeouts
    wazuh_api_timeout: int = 30
    llm_api_timeout: int = 60
    
    # Decision Confidence Threshold
    min_decision_confidence: float = 0.75  # Minimum confidence to enforce DENY

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False
    )


@lru_cache()
def get_settings() -> Settings:
    """Cached settings instance"""
    return Settings()
