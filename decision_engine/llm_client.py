"""
LLM Client - IoT-Access-Sentinel Decision Engine
Wrapper for LLM API calls (OpenAI/Gemini)
Uses new google.genai SDK (google-genai package)
"""

from typing import Any, Union, Optional
from config.settings import Settings
from common.logging_config import get_logger
from openai import AsyncOpenAI
from google import genai

logger = get_logger(__name__)


def get_llm_client(settings: Settings, required: bool = True) -> Optional[Union[AsyncOpenAI, genai.Client]]:
    """
    Get LLM client based on settings or environment variables.
    
    Args:
        settings: Application settings
        required: Whether to raise ValueError if API key is missing (default True)
    
    Returns:
        AsyncOpenAI client, Gemini client, or None if not required and not configured
    
    Raises:
        ValueError: If required is True and LLM provider is not configured correctly
    """
    import os
    from dotenv import dotenv_values
    
    provider = settings.llm_provider.lower()
    
    # Try reading from .env if present
    env_vals = {}
    try:
        env_vals = dotenv_values(".env")
    except Exception:
        pass
    
    # Resolve API keys from .env, settings, and os.environ
    openai_key = (
        env_vals.get("OPENAI_API_KEY") 
        or env_vals.get("GROQ_API_KEY") 
        or settings.openai_api_key 
        or os.environ.get("OPENAI_API_KEY") 
        or os.environ.get("GROQ_API_KEY")
    )
    gemini_key = (
        env_vals.get("GEMINI_API_KEY") 
        or settings.gemini_api_key 
        or os.environ.get("GEMINI_API_KEY")
    )
    
    if provider == "openai":
        api_key = openai_key
        base_url = (
            env_vals.get("OPENAI_BASE_URL") 
            or settings.openai_base_url 
            or os.environ.get("OPENAI_BASE_URL")
        )
        
        if not api_key:
            if not required:
                logger.info("openai_key_not_configured_llm_optional")
                return None
            raise ValueError("OpenAI/Groq API key not configured. Set OPENAI_API_KEY or GROQ_API_KEY in .env or environment")
        
        # If using a Groq key (starts with gsk_) or GROQ endpoint
        if api_key.startswith("gsk_") or "groq.com" in (base_url or "").lower() or os.environ.get("GROQ_API_KEY"):
            base_url = base_url or "https://api.groq.com/openai/v1"
            # Groq does not have gpt-4; fallback to a valid Groq model
            if settings.llm_model == "gpt-4":
                settings.llm_model = "llama-3.1-8b-instant"
                logger.info("groq_model_adjusted", model=settings.llm_model)
            
        logger.info("creating_openai_client", model=settings.llm_model, base_url=base_url or "default")
        
        # Create OpenAI async client (supports Groq and other OpenAI-compatible APIs)
        import httpx
        client_kwargs = {
            "api_key": api_key,
            "timeout": httpx.Timeout(connect=5.0, read=30.0, write=10.0, pool=5.0),
            "default_headers": {
                "User-Agent": "IoT-Access-Sentinel/0.1.0"
            }
        }
        if base_url:
            client_kwargs["base_url"] = base_url
        
        client = AsyncOpenAI(**client_kwargs)
        return client
    
    elif provider == "gemini":
        if not gemini_key:
            if not required:
                logger.info("gemini_key_not_configured_llm_optional")
                return None
            raise ValueError("Gemini API key not configured. Set GEMINI_API_KEY in .env or environment")
        
        logger.info("creating_gemini_client", model=settings.llm_model)
        client = genai.Client(api_key=gemini_key)
        return client
    
    elif provider == "ollama":
        # TODO: Ollama client
        logger.warning(
            "ollama_not_supported_yet",
            message="Ollama support requires additional implementation. Falling back to OpenAI."
        )
        if not settings.openai_api_key:
            raise ValueError("OpenAI API key required as fallback. Set OPENAI_API_KEY in .env")
        
        return AsyncOpenAI(
            api_key=settings.openai_api_key,
            default_headers={
                "User-Agent": "IoT-Access-Sentinel/0.1.0"
            }
        )
    
    else:
        raise ValueError(f"Unsupported LLM provider: {provider}. Use 'openai' or 'gemini'")


async def test_llm_connection(settings: Settings) -> bool:
    """
    Test LLM API connectivity
    
    Args:
        settings: Application settings
    
    Returns:
        True if connection successful, False otherwise
    """
    try:
        client = get_llm_client(settings)
        logger.info(
            "llm_client_created",
            provider=settings.llm_provider,
            model=settings.llm_model
        )
        return True
    except Exception as e:
        logger.error(
            "llm_connection_test_failed",
            provider=settings.llm_provider,
            error=str(e)
        )
        return False
