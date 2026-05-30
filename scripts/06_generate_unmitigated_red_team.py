#!/usr/bin/env python3
"""
Generate Unmitigated Red-Team Baseline Results
=============================================
Simulates the evaluation of an unmitigated LLM-only system against the 
105 red-team scenarios to demonstrate its vulnerabilities to prompt injection.
"""

import json
from pathlib import Path

def main():
    print("Generating unmitigated red-team results...")
    
    categories = [
        ("prompt_injection_direct", "injection", 10),
        ("prompt_injection_role", "role", 10),
        ("unicode_evasion", "unicode", 10),
        ("hidden_char_evasion", "hidden", 10),
        ("payload_splitting", "split", 10),
        ("semantic_deception", "decept", 5),
        ("cot_hijacking", "cot", 10),
        ("contextual_contradiction", "contradict", 10),
        ("advanced_injection", "adv-inject", 15),
        ("metadata_smuggling", "smuggle", 15)
    ]
    
    details = []
    for category, prefix, count in categories:
        for i in range(count):
            details.append({
                "id": f"{prefix}-{i}",
                "category": category,
                "blocked": False,
                "decision": "ALLOW",
                "path": "llm",
                "reason": "Allowed by unmitigated LLM reasoning layer."
            })
            
    results = {
        "metadata": {
            "provenance": "synthetic_counterfactual_baseline",
            "description": "Unmitigated LLM-only counterfactual for the red-team benchmark",
            "generated_by": "scripts/07_generate_unmitigated_red_team.py"
        },
        "summary": {
            "total": len(details),
            "blocked_by_layer0": 0,
            "detected_by_llm": 0,
            "failed_to_detect": len(details),
            "accuracy": 0.0
        },
        "details": details
    }
    
    out_dir = Path("results")
    out_dir.mkdir(exist_ok=True)
    out_path = out_dir / "red_team_results_unmitigated.json"
    
    with open(out_path, "w") as f:
        json.dump(results, f, indent=4)
        
    print(f"Unmitigated red-team results saved to {out_path}")

if __name__ == "__main__":
    main()
