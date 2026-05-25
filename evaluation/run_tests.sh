#!/bin/bash
# Simple bash-based test runner using curl

API_URL="http://localhost:8000"
SCENARIOS_DIR="evaluation/scenarios"
RESULTS_FILE="results/test_$(date +%Y%m%d_%H%M%S).txt"

mkdir -p results

echo "==========================================================" | tee "$RESULTS_FILE"
echo "IoT-Access-Sentinel - Test Suite" | tee -a "$RESULTS_FILE"
echo "==========================================================" | tee -a "$RESULTS_FILE"
echo "" | tee -a "$RESULTS_FILE"

# Counter variables
total=0
passed=0
failed=0

# Run each test
for test_file in "$SCENARIOS_DIR"/*.json; do
    if [ ! -f "$test_file" ]; then
        continue
    fi
    
    total=$((total + 1))
    filename=$(basename "$test_file")
    
    echo "Test $total: $filename" | tee -a "$RESULTS_FILE"
    
    # Extract expected decision using python for reliable JSON parsing
    expected=$(python3 -c "import json; data=json.load(open('$test_file')); print(data.get('expected_decision', 'UNKNOWN'))")
    
    # Make API call
    response=$(curl -s -X POST "$API_URL/access-control" \
        -H "Content-Type: application/json" \
        -H "Authorization: sentinel-webhook-secret-key" \
        -d @"$test_file")
    
    # Extract actual decision using python
    actual=$(echo "$response" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data.get('decision_action', 'ERROR'))")
    confidence=$(echo "$response" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data.get('decision_confidence', 0))")
    
    # Check result
    if [ "$expected" == "$actual" ]; then
        echo "  PASS - Expected: $expected, Got: $actual, Confidence: $confidence" | tee -a "$RESULTS_FILE"
        passed=$((passed + 1))
    else
        echo "  FAIL - Expected: $expected, Got: $actual, Confidence: $confidence" | tee -a "$RESULTS_FILE"
        failed=$((failed + 1))
    fi
    
    echo "" | tee -a "$RESULTS_FILE"
    
    # Delay between tests to avoid rate limits (10 RPM = 1 request per 6s minimum)
    # Using 8s to be safe
    sleep 8
done

echo "==========================================================" | tee -a "$RESULTS_FILE"
echo "SUMMARY" | tee -a "$RESULTS_FILE"
echo "==========================================================" | tee -a "$RESULTS_FILE"
echo "Total Tests: $total" | tee -a "$RESULTS_FILE"
echo "Passed: $passed" | tee -a "$RESULTS_FILE"
echo "Failed: $failed" | tee -a "$RESULTS_FILE"

if [ $total -gt 0 ]; then
    accuracy=$(awk "BEGIN {printf \"%.1f\", ($passed/$total)*100}")
    echo "Accuracy: $accuracy%" | tee -a "$RESULTS_FILE"
fi

echo "" | tee -a "$RESULTS_FILE"
echo "Full results saved to: $RESULTS_FILE" | tee -a "$RESULTS_FILE"
