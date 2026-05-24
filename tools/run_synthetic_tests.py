#!/usr/bin/env python3
"""
Automated Synthetic Test Runner
Tests all generated scenarios and produces results report
"""

import json
import requests
import sys
from pathlib import Path
from datetime import datetime

PROJECT_ROOT = Path(__file__).parent.parent
SYNTHETIC_DIR = PROJECT_ROOT / "evaluation" / "synthetic"
RESULTS_DIR = PROJECT_ROOT / "results"
API_URL = "http://localhost:8000/access-control"

def main():
    # Check server
    try:
        requests.get("http://localhost:8000/", timeout=2)
    except:
        print("❌ Error: Server not running on http://localhost:8000")
        print("Start with: ./venv/bin/python main.py")
        sys.exit(1)
    
    print("=" * 50)
    print("Synthetic Scenario Testing")
    print("=" * 50)
    print()
    
    # Load summary
    summary_file = SYNTHETIC_DIR / "summary.json"
    if summary_file.exists():
        with open(summary_file) as f:
            summary = json.load(f)
            print(f"Total scenarios: {summary['total_scenarios']}")
            print()
    
    # Collect all test files
    test_files = sorted([f for f in SYNTHETIC_DIR.glob("*.json") 
                        if f.name != "summary.json"])
    
    passed = 0
    failed = 0
    results = []
    
    for i, scenario_file in enumerate(test_files, 1):
        with open(scenario_file) as f:
            scenario = json.load(f)
        
        scenario_id = scenario_file.stem
        expected = scenario.get("expected_decision", "UNKNOWN")
        
        # Make API call
        try:
            headers = {"Authorization": "sentinel-webhook-secret-key"}
            response = requests.post(API_URL, json=scenario, headers=headers, timeout=30)
            result = response.json()
            actual = result.get("decision_action", "ERROR")
            confidence = result.get("decision_confidence", 0)
        except Exception as e:
            actual = "ERROR"
            confidence = 0
            print(f"  ❌ {scenario_id}: API error - {e}")
        
        # Check result
        if expected == actual:
            passed += 1
            status = "PASS"
        else:
            failed += 1
            status = "FAIL"
            print(f"  ❌ {scenario_id}: Expected {expected}, Got {actual}")
        
        results.append({
            "scenario": scenario_id,
            "expected": expected,
            "actual": actual,
            "confidence": confidence,
            "status": status
        })
        
        # Progress
        if i % 10 == 0:
            print(f"  Tested {i}/{len(test_files)} scenarios...")
    
    # Calculate accuracy
    total = passed + failed
    accuracy = (passed / total * 100) if total > 0 else 0
    
    # Save results
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    results_file = RESULTS_DIR / f"synthetic_test_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    
    output = {
        "test_run": datetime.now().isoformat(),
        "results": results,
        "summary": {
            "total": total,
            "passed": passed,
            "failed": failed,
            "accuracy": f"{accuracy:.1f}%"
        }
    }
    
    with open(results_file, 'w') as f:
        json.dump(output, f, indent=2)
    
    # Print summary
    print()
    print("=" * 50)
    print("SUMMARY")
    print("=" * 50)
    print(f"Total Tests: {total}")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")
    print(f"Accuracy: {accuracy:.1f}%")
    print()
    print(f"Results saved to: {results_file}")

if __name__ == "__main__":
    main()
