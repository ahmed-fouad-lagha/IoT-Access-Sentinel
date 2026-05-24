#!/usr/bin/env python3
"""
Simple test runner for single JSON test scenarios
"""
import sys
import json
import requests

def run_single_test(test_file: str):
    """Run a single test scenario"""
    # Load test scenario
    with open(test_file, 'r') as f:
        test = json.load(f)
    
    print(f"Running test: {test_file}")
    
    # Extract expected decision and alert data
    if 'alert' in test:
        # Format: {"alert": {...}, "expected_action": "..."}
        alert_data = test['alert']
        expected = test['expected_action']
    else:
        # Format: {... (alert fields), "expected_decision": "..."}
        alert_data = {k: v for k, v in test.items() if k not in ['expected_decision', 'test_category', 'description']}
        expected = test['expected_decision']
    
    print(f"Expected: {expected}")
    
    # Send to API
    response = requests.post(
        "http://localhost:8000/access-control",
        json=alert_data,
        headers={"Authorization": "sentinel-webhook-secret-key"}
    )
    
    if response.status_code == 200:
        result = response.json()
        actual_action = result.get('decision_action', 'UNKNOWN')
        print(f"Actual:   {actual_action}")
        print(f"Reason:   {result.get('decision_reason', 'No reason')}")
        print(f"Confidence: {result.get('decision_confidence', 0.0)}")
        
        if actual_action == expected:
            print("✅ PASS")
            return True
        else:
            print("❌ FAIL")
            return False
    else:
        print(f"❌ API ERROR: {response.status_code}")
        print(response.text)
        return False

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python run_single_test.py <test_file.json>")
        sys.exit(1)
    
    success = run_single_test(sys.argv[1])
    sys.exit(0 if success else 1)
