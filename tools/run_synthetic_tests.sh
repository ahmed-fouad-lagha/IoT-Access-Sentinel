#!/bin/bash
# Automated Synthetic Test Runner
# Tests all generated scenarios against IoT-Access-Sentinel

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
SYNTHETIC_DIR="$PROJECT_ROOT/tests/synthetic"
RESULTS_DIR="$PROJECT_ROOT/tests/results"
API_URL="http://localhost:8000/access-control"

# Create results directory
mkdir -p "$RESULTS_DIR"

# Check if server is running
if ! curl -s "$API_URL" > /dev/null 2>&1; then
    echo "❌ Error: IoT-Access-Sentinel server not running on $API_URL"
    echo "Start with: ./venv/bin/python main.py"
    exit 1
fi

echo "=========================================="
echo "Synthetic Scenario Testing"
echo "=========================================="
echo ""

# Read summary
if [ -f "$SYNTHETIC_DIR/summary.json" ]; then
    TOTAL=$(python3 -c "import json; print(json.load(open('$SYNTHETIC_DIR/summary.json'))['total_scenarios'])")
    echo "Total scenarios: $TOTAL"
    echo ""
fi

# Initialize counters
PASSED=0
FAILED=0
RESULTS_FILE="$RESULTS_DIR/synthetic_test_$(date +%Y%m%d_%H%M%S).json"

echo "{" > "$RESULTS_FILE"
echo '  "test_run": "'$(date -Iseconds)'",' >> "$RESULTS_FILE"
echo '  "results": [' >> "$RESULTS_FILE"

FIRST=true

# Test each scenario
for scenario_file in "$SYNTHETIC_DIR"/*.json; do
    # Skip summary file
    if [[ "$(basename "$scenario_file")" == "summary.json" ]]; then
        continue
    fi
    
    SCENARIO_ID=$(basename "$scenario_file" .json)
    
    # Get expected decision
    EXPECTED=$(python3 -c "import json; print(json.load(open('$scenario_file')).get('expected_decision', 'UNKNOWN'))")
    
    # Make API call
    RESPONSE=$(curl -s -X POST "$API_URL" \
        -H "Content-Type: application/json" \
        -d @"$scenario_file")
    
    # Extract actual decision
    ACTUAL=$(echo "$RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin).get('decision_action', 'ERROR'))" 2>/dev/null || echo "ERROR")
    
    # Check result
    if [ "$EXPECTED" == "$ACTUAL" ]; then
        ((PASSED++))
        STATUS="PASS"
    else
        ((FAILED++))
        STATUS="FAIL"
        echo "  ❌ $SCENARIO_ID: Expected $EXPECTED, Got $ACTUAL"
    fi
    
    # Add to results JSON
    if [ "$FIRST" = true ]; then
        FIRST=false
    else
        echo "," >> "$RESULTS_FILE"
    fi
    
    echo -n '    {"scenario": "'$SCENARIO_ID'", "expected": "'$EXPECTED'", "actual": "'$ACTUAL'", "status": "'$STATUS'"}' >> "$RESULTS_FILE"
done

echo "" >> "$RESULTS_FILE"
echo "  ]," >> "$RESULTS_FILE"

TOTAL=$((PASSED + FAILED))
if [ $TOTAL -gt 0 ]; then
    ACCURACY=$(python3 -c "print(f'{$PASSED/$TOTAL*100:.1f}')")
else
    ACCURACY="0.0"
fi

echo '  "summary": {' >> "$RESULTS_FILE"
echo '    "total": '$TOTAL',' >> "$RESULTS_FILE"
echo '    "passed": '$PASSED',' >> "$RESULTS_FILE"
echo '    "failed": '$FAILED',' >> "$RESULTS_FILE"
echo '    "accuracy": "'$ACCURACY'%"' >> "$RESULTS_FILE"
echo '  }' >> "$RESULTS_FILE"
echo "}" >> "$RESULTS_FILE"

echo ""
echo "=========================================="
echo "SUMMARY"
echo "=========================================="
echo "Total Tests: $TOTAL"
echo "Passed: $PASSED"
echo "Failed: $FAILED"
echo "Accuracy: $ACCURACY%"
echo ""
echo "Results saved to: $RESULTS_FILE"
