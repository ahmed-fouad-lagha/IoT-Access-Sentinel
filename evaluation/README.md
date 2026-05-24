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
bash evaluation/run_tests.sh
```

### Expected Output

```
IoT-Access-Sentinel - Manual Test Suite
==========================================================

Loaded 8 test scenarios from evaluation/scenarios

[Each test runs with detailed output showing:]
- Test ID and category
- Expected vs actual decision
- Confidence score
- Response time
- Pass/Fail result

TEST RESULTS SUMMARY
============================================================
Total Tests: 8
Successful API Calls: 8
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
results/test_results_YYYYMMDD_HHMMSS.json
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
