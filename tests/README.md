# Test Suite Documentation

## Overview

Comprehensive test suite for validating the IoT-Access-Sentinel LLM Decision Engine.

## Test Scenarios

### Camera Tests (5 scenarios)

**ALLOW Cases:**
1. `camera_allow_1.json` - Valid camera during business hours (10:00)
2. `camera_allow_2.json` - Camera at boundary time (09:00 exactly)

**DENY Cases:**
3. `camera_deny_1.json` - Camera outside business hours (22:00)
4. `camera_deny_2.json` - Camera from unauthorized network (10.5.5.100)
5. `camera_deny_3.json` - Unknown camera (no device_id)

### Sensor Tests (2 scenarios)

**ALLOW Cases:**
6. `sensor_allow_1.json` - Valid sensor at night (sensors allowed 24/7)

**DENY Cases:**
7. `sensor_deny_1.json` - Sensor from wrong network (172.16.0.0/24)

### Smart Lock Tests (1 scenario)

**DENY Cases:**
8. `smartlock_deny_1.json` - Smart lock without 2FA metadata

## Running Tests

### Prerequisites

Server must be running:
```bash
./venv/bin/python main.py
```

### Run All Tests

```bash
python3 tests/run_tests.py
```

Or:
```bash
./tests/run_tests.py
```

### Expected Output

```
IoT-Access-Sentinel - Comprehensive Test Suite
============================================================

Loaded 10 test scenarios from tests/scenarios

[Each test runs with detailed output showing:]
- Test ID and category
- Expected vs actual decision
- Confidence score
- Response time
- Pass/Fail result

TEST RESULTS SUMMARY
============================================================
Total Tests: 10
Successful API Calls: 10
Correct Decisions: X
Accuracy: XX.X%

Response Time:
  Average: XX.XXs
  Min: XX.XXs
  Max: XX.XXs

Average Confidence: 0.XX

Results by Category:
  camera_valid: X/X (XXX%)
  camera_boundary: X/X (XXX%)
  ...
```

## Results Storage

Results are automatically saved to:
```
tests/results/test_results_YYYYMMDD_HHMMSS.json
```

JSON format includes:
- Summary statistics
- Per-test results
- Response times
- Confidence scores
- Reasons for each decision

## Evaluation Metrics

The test suite calculates:

1. **Accuracy** = Correct Decisions / Total Tests
2. **Response Time** (avg, min, max)
3. **Confidence Score** (average across all tests)
4. **Per-Category Accuracy** (broken down by test type)

## Test Scenario Format

Each test JSON file includes:
```json
{
  "id": "test-id",
  "timestamp": "ISO timestamp",
  "rule": {...},
  "device_id": "device identifier or null",
  "device_type": "camera|sensor|smart_lock",
  "source_ip": "source IP address",
  "expected_decision": "ALLOW or DENY",
  "test_category": "test category label",
  "description": "what this test validates"
}
```

## Adding New Tests

1. Create new JSON file in `tests/scenarios/`
2. Follow the test scenario format
3. Include `expected_decision` and `test_category`
4. Run test suite - new tests auto-discovered

## Interpreting Results

### High Accuracy (>90%)
✅ LLM decision engine is working well
✅ Policies are correctly interpreted
✅ Context analysis is effective

### Medium Accuracy (70-90%)
⚠️ Some edge cases may need attention
⚠️ Policy definitions may need refinement
⚠️ Consider prompt engineering improvements

### Low Accuracy (<70%)
❌ Significant issues with decision logic
❌ Review policy definitions
❌ Check LLM prompt engineering
❌ Verify test scenarios are valid

## Known Limitations

1. **LLM Conservatism**: Gemini tends to be strict ("when in doubt, DENY")
   - High-severity alerts (level 8+) often trigger DENY
   - Missing historical data can cause DENY
   
2. **Response Time**: ~25-40 seconds per decision
   - Sequential tests to avoid rate limits
   - Full suite may take 5-10 minutes

3. **Gemini Free Tier**: 60 requests/min, 1,500/day
   - Adequate for development
   - May need paid tier for large-scale testing

## Next Steps

After running tests:
1. Review accuracy metrics
2. Analyze failed tests
3. Adjust policies or prompts if needed
4. Compare vs simple baseline (future)
5. Document results for research paper
