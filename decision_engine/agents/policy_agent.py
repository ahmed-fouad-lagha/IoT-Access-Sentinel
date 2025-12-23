"""
Policy Agent - IoT-Access-Sentinel Decision Engine
LLM-based policy interpreter supporting OpenAI and Gemini
Uses new google.genai SDK
"""

from typing import Dict, Any, Union
from openai import AsyncOpenAI
from google import genai

from common.logging_config import get_logger

logger = get_logger(__name__)


POLICY_AGENT_SYSTEM_MESSAGE = """You are a Policy Interpreter for IoT Access Control.

Your role is to analyze IoT device connection attempts against defined access policies and determine if access should be ALLOWED or DENIED.

**Your Input:**
- Device information (type, ID, source IP)
- Connection context (timestamp, protocol, destination)
- Access control policies (allowed hours, networks, rate limits)

**Your Decision Criteria:**
1. **Time-based**: Is the connection within allowed hours/days?
2. **Network-based**: Is the source IP from an allowed network?
3. **Rate-limiting**: Has the device exceeded connection limits?
4. **Device-specific**: Are there special requirements (e.g., 2FA for smart locks)?

**Decision Guidelines:**
- **ALLOW** if ALL policy conditions are met and no explicit violations exist
- **DENY** if ANY mandatory policy condition is violated
- **CRITICAL:** If rule ID "100040" (Unknown Device) is present, you MUST DENY regardless of other valid factors
- For unknown/missing data: 
  - Missing historical data alone is NOT a reason to deny
  - Alert levels 5-7 are routine monitoring, not violations
  - Only alert levels 8+ indicate significant anomalies
- When policies are satisfied, trust the match - don't invent reasons to deny

**Your Output Format:**
You must respond in this exact JSON format:
{
    "action": "ALLOW" or "DENY",
    "confidence": <float between 0.0 and 1.0>,
    "reason": "<clear explanation>",
    "policy_matched": "<policy name or 'default'>"
}

**Important:**
- Apply policies accurately - not overly strict
- High confidence (>0.9) for clear policy matches
- Lower confidence (0.6-0.8) for edge cases or ambiguity
- Deny only when policies explicitly prohibit OR clear security violations exist
"""


async def call_policy_agent(client: Union[AsyncOpenAI, genai.Client], model: str, prompt: str, provider: str = "openai") -> str:
    """
    Call Policy Agent using OpenAI or Gemini API
    
    Args:
        client: AsyncOpenAI client or Gemini Client
        model: Model name
        prompt: User prompt
        provider: "openai" or "gemini"
    
    Returns:
        LLM response text
    """
    logger.debug("calling_policy_agent", provider=provider)
    
    if provider == "gemini":
        # Use new Gemini API
        full_prompt = f"{POLICY_AGENT_SYSTEM_MESSAGE}\n\n{prompt}"
        response = client.models.generate_content(
            model=model,
            contents=full_prompt
        )
        return response.text
    else:
        # Use OpenAI API
        response = await client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": POLICY_AGENT_SYSTEM_MESSAGE},
                {"role": "user", "content": prompt}
            ],
            temperature=0.1,
            max_tokens=512
        )
        return response.choices[0].message.content
