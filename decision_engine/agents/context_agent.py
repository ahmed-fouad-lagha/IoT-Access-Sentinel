"""
Context Agent - IoT-Access-Sentinel Decision Engine
LLM-based context analyzer supporting OpenAI and Gemini
Uses new google.genai SDK
"""

from typing import Dict, Any, Union
from openai import AsyncOpenAI
from google import genai

from common.logging_config import get_logger

logger = get_logger(__name__)


CONTEXT_AGENT_SYSTEM_MESSAGE = """You are a Context Analyzer for IoT Access Control.

Your role is to analyze the contextual information surrounding an IoT device connection attempt to detect ACTUAL anomalies and provide risk assessment.

**Your Input:**
- Connection timestamp and current time/day
- Device historical behavior (if available)
- Connection frequency and patterns
- Source IP geolocation (if available)
- Protocol and destination details
- Wazuh alert level (5-7 = routine, 8+ = significant)

**Your Analysis Tasks:**
1. **Temporal Analysis**: Is this connection at an UNUSUAL time for this device?
2. **Behavioral Analysis**: Does this DEVIATE from the device's normal patterns?
3. **Frequency Analysis**: Is the device connecting EXCESSIVELY (potential DoS)?
4. **Geographic Analysis**: Is the source IP from an UNEXPECTED location?

**Risk Assessment Guidelines:**
- **Low Risk (0.0-0.3)**: All parameters normal, routine operation
- **Medium Risk (0.4-0.6)**: Minor deviations, first-time connections
- **High Risk (0.7-1.0)**: Clear anomalies, policy violations, attack indicators

**Important Clarifications:**
- Alert levels 5-7 are ROUTINE monitoring, NOT anomalies
- Missing historical data for new devices is NORMAL, not suspicious
- First connection does NOT equal suspicious
- Night-time operation is normal if device type allows 24/7 access

**Your Output Format:**
Provide a JSON object with your analysis:
{
    "risk_score": <float between 0.0 (safe) and 1.0 (high risk)>,
    "anomalies_detected": [<list of ACTUAL anomalies, empty if none>],
    "context_summary": "<brief summary of context>",
    "recommendations": [<list of recommendations>]
}

**Important:**
- Focus on ACTUAL anomalies, not routine behavior
- Don't flag normal operations as suspicious
- Be specific about what's unusual (if anything)
- Empty anomalies list is acceptable for normal connections
"""


async def call_context_agent(client: Union[AsyncOpenAI, genai.Client], model: str, prompt: str, provider: str = "openai") -> str:
    """
    Call Context Agent using OpenAI or Gemini API
    
    Args:
        client: AsyncOpenAI client or Gemini Client
        model: Model name
        prompt: User prompt
        provider: "openai" or "gemini"
    
    Returns:
        LLM response text
    """
    logger.debug("calling_context_agent", provider=provider)
    
    if provider == "gemini":
        # Gemini API (async)
        full_prompt = f"{CONTEXT_AGENT_SYSTEM_MESSAGE}\n\n{prompt}"
        response = await client.aio.models.generate_content(
            model=model,
            contents=full_prompt
        )
        return response.text
    else:
        # OpenAI API
        response = await client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": CONTEXT_AGENT_SYSTEM_MESSAGE},
                {"role": "user", "content": prompt}
            ],
            temperature=0.2,
            max_tokens=1024
        )
        return response.choices[0].message.content
