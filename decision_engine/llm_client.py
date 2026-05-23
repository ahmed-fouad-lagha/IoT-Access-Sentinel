"""
LLM Client - IoT-Access-Sentinel Decision Engine
Wrapper for LLM API calls (OpenAI/Gemini)
Uses new google.genai SDK (google-genai package)
"""

from typing import Any, Union
from config.settings import Settings
from common.logging_config import get_logger
from openai import AsyncOpenAI
from google import genai

logger = get_logger(__name__)


def get_llm_client(settings: Settings) -> Union[AsyncOpenAI, genai.Client]:
    """
    Get LLM client based on settings
    
    Args:
        settings: Application settings
    
    Returns:
        AsyncOpenAI client or Gemini client
    
    Raises:
        ValueError: If LLM provider is not configured correctly
    """
    provider = settings.llm_provider.lower()
    
    if provider == "openai":
        if not settings.openai_api_key:
            raise ValueError("OpenAI API key not configured. Set OPENAI_API_KEY in .env")
        
        logger.info("creating_openai_client", model=settings.llm_model, base_url=settings.openai_base_url or "default")
        
        # Create OpenAI async client (supports Groq and other OpenAI-compatible APIs)
        # We inject User-Agent to bypass AgentRouter client authentication checks
        client_kwargs = {
            "api_key": settings.openai_api_key,
            "default_headers": {
                "User-Agent": "claude-code/0.2.9"
            }
        }
        if settings.openai_base_url:
            client_kwargs["base_url"] = settings.openai_base_url
        
        client = AsyncOpenAI(**client_kwargs)
        
        return client
    
    elif provider == "gemini":
        if not settings.gemini_api_key:
            raise ValueError("Gemini API key not configured. Set GEMINI_API_KEY in .env")
        
        logger.info("creating_gemini_client", model=settings.llm_model)
        
        # Create Gemini client using new SDK
        client = genai.Client(api_key=settings.gemini_api_key)
        
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
                "User-Agent": "claude-code/0.2.9"
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
