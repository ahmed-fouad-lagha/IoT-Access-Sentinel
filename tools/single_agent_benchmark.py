import asyncio
import json
import yaml
from datetime import datetime
from pathlib import Path
import sys
import os

# Add root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.logging_config import setup_logging
from common.schemas import AccessDecision
from config.settings import get_settings
from decision_engine.llm_client import get_llm_client
from observer.models import IoTAccessAlert

setup_logging("INFO")

class SingleAgentPipeline:
    def __init__(self, settings):
        self.settings = settings
        self.llm_client = get_llm_client(settings)
        self.model = settings.llm_model
        
        with open(settings.policy_file_path, 'r') as f:
            self.policies = yaml.safe_load(f)

    async def make_decision(self, alert: IoTAccessAlert) -> dict:
        policies_text = yaml.dump(self.policies, default_flow_style=False)
        provider = self.settings.llm_provider.lower()
        
        # Combined prompt: Context + Policy
        prompt = f"""Analyze the IoT connection attempt and make an access control decision based on the provided policies.

**Connection Details:**
Device Type: {alert.device_type or 'Unknown'}
Device ID: {alert.device_id or 'Unknown'}
Source IP: {alert.source_ip or 'Unknown'}
Destination: {alert.destination_ip}:{alert.destination_port}
Protocol: {alert.protocol or 'Unknown'}
Timestamp: {alert.timestamp}
Current Time: {datetime.now().isoformat()}
Wazuh Rule: {alert.rule.description} (Level {alert.rule.level})

**User Authorization (M0801):**
User ID: {alert.user_id or 'Missing'}
Auth Token: {alert.auth_token or 'Missing'}
User Role: {alert.user_role or 'Unknown'}

**Access Policies:**
{policies_text}

**Instructions:**
1. Identify potential risks or anomalies in the connection attempt.
2. Evaluate the connection against the access policies.
3. Provide a final decision (ALLOW/DENY).

Return your response as a JSON object with the following fields:
- "action": Use "ALLOW" or "DENY"
- "confidence": Float between 0 and 1
- "reason": A brief explanation of the decision
- "risk_score": Float between 0 and 1
- "policy_matched": Name of the policy that applied

TERMINATE after the JSON block.
"""
        
        if provider == "gemini":
            response = self.llm_client.models.generate_content(
                model=self.model,
                contents=prompt
            )
            response_text = response.text
        else:
            response = await self.llm_client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a Single-Agent IoT Security Controller."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1
            )
            response_text = response.choices[0].message.content
        
        # Parse JSON
        try:
            json_start = response_text.find("{")
            json_end = response_text.rfind("}") + 1
            if json_start >= 0 and json_end > json_start:
                return json.loads(response_text[json_start:json_end])
            return {"action": "DENY", "confidence": 1.0, "reason": "Single-agent parse error", "error": True}
        except Exception:
            return {"action": "DENY", "confidence": 1.0, "reason": "Single-agent exception", "error": True}

async def run_benchmark():
    settings = get_settings()
    pipeline = SingleAgentPipeline(settings)
    
    # Locate all test scenarios
    test_dir = Path("tests")
    test_files = list(test_dir.rglob("*.json"))
    
    # Filter and prioritize
    test_files = [f for f in test_files if "report" not in f.name and "summary" not in f.name and "results" not in f.name]
    
    # Prioritize hard categories
    priority_cats = ["extended_red_team", "red_team", "edge_cases", "device_specific"]
    test_files.sort(key=lambda x: 0 if x.parent.name in priority_cats else 1)
    
    # Limit to 30 scenarios to beat rate limits while getting high-value data
    test_files = test_files[:30]
    
    results = {
        'total': 0,
        'correct': 0,
        'errors': 0,
        'decisions': [],
        'categories': {}
    }
    
    print(f"🚀 Running Single-Agent Benchmark ({len(test_files)} scenarios)")
    print("-" * 60)

    for test_file in test_files:
        with open(test_file, 'r') as f:
            try:
                data = json.load(f)
            except Exception:
                continue
        
        expected = data.get("expected_decision")
        if not expected:
            continue
            
        category = test_file.parent.name
        if category not in results['categories']:
            results['categories'][category] = {'correct': 0, 'total': 0}
            
        alert = IoTAccessAlert(**data)
        
        # Rate limit safety
        await asyncio.sleep(0.1)
        
        try:
            decision = await pipeline.make_decision(alert)
            actual = decision.get("action")
            is_correct = (actual == expected)
            
            results['total'] += 1
            results['categories'][category]['total'] += 1
            
            if is_correct:
                results['correct'] += 1
                results['categories'][category]['correct'] += 1
                print(f"✅ {test_file.name}: {actual} (Expected: {expected})")
            else:
                print(f"❌ {test_file.name}: {actual} (Expected: {expected})")
                
            results['decisions'].append({
                'file': str(test_file),
                'category': category,
                'expected': expected,
                'actual': actual,
                'correct': is_correct,
                'reason': decision.get("reason"),
                'confidence': decision.get("confidence")
            })
            
        except Exception as e:
            print(f"Error processing {test_file}: {e}")
            results['errors'] += 1
            results['total'] += 1

    # Save results
    output_file = "single_agent_results.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)

if __name__ == "__main__":
    asyncio.run(run_benchmark())
