# Custom IoT Rules and Decoders Documentation

## Overview
Custom Wazuh rules and decoders for detecting and classifying IoT device access attempts.

## Files Created

### 1. Decoders (`decoders/iot_access_decoder.xml`)
Parses IoT access logs and extracts:
- Device type (camera, sensor, smart_lock)
- Device ID
- Source/Destination IPs
- Protocol information

**Log Format Expected:**
```
iot-access: camera device_id=camera-office-01 src_ip=192.168.1.100 dst_ip=10.0.0.1:443 proto=HTTPS
```

### 2. Rules (`rules/iot_access_rules.xml`)

#### Rule ID Ranges
- **100000-100099**: Base IoT events
- **100010-100019**: Camera events
- **100020-100029**: Sensor events
- **100030-100039**: Smart lock events
- **100040-100049**: Unknown device events

#### Key Rules

**Cameras (100010-100019)**
- `100010` (Level 5): Camera connection attempt
- `100011` (Level 7): Camera outside business hours (21:00-09:00)
- `100012` (Level 8): Camera from unauthorized network

**Sensors (100020-100029)**
- `100020` (Level 4): Sensor telemetry
- `100021` (Level 7): Sensor from wrong network
- `100022` (Level 6): High frequency (>20 in 60s, possible DoS)

**Smart Locks (100030-100039)**
- `100030` (Level 6): Lock access attempt
- `100031` (Level 9): Lock access requiring 2FA

**Unknown Devices (100040-100049)**
- `100040` (Level 8): Unknown device
- `100041` (Level 9): Repeated unknown attempts (5 in 5min)

## Installation to Wazuh

### Copy to Wazuh Manager Container

```bash
# Decoders
docker cp config/wazuh/decoders/iot_access_decoder.xml \
  single-node-wazuh.manager-1:/var/ossec/etc/decoders/iot_access_decoder.xml

# Rules
docker cp config/wazuh/rules/iot_access_rules.xml \
  single-node-wazuh.manager-1:/var/ossec/etc/rules/iot_access_rules.xml
```

### Restart Wazuh Manager

```bash
docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control restart
```

### Verify Installation

```bash
# Check decoder
docker exec single-node-wazuh.manager-1 \
  /var/ossec/bin/wazuh-logtest -v

# Test with sample log
echo "iot-access: camera device_id=test-cam-01 src_ip=192.168.1.100 dst_ip=10.0.0.1:443 proto=HTTPS" | \
  docker exec -i single-node-wazuh.manager-1 /var/ossec/bin/wazuh-logtest
```

## Network Policies Defined

| Device Type | Allowed Network | Time Restriction | Alert Level |
|-------------|----------------|------------------|-------------|
| Camera | 192.168.1.0/24 | 09:00-21:00 | 5 (normal), 7-8 (violation) |
| Sensor | 192.168.2.0/24 | 24/7 | 4 (normal), 7 (violation) |
| Smart Lock | 192.168.3.0/24 | Requires 2FA | 9 (high security) |
| Unknown | - | - | 8-9 (threat) |

## Testing

### Generate Test Logs

```bash
# Camera - Valid
logger -t iot-access "camera device_id=camera-office-01 src_ip=192.168.1.100 dst_ip=10.0.0.1:443 proto=HTTPS"

# Camera - Invalid network
logger -t iot-access "camera device_id=camera-office-01 src_ip=10.5.5.100 dst_ip=10.0.0.1:443 proto=HTTPS"

# Sensor - Valid
logger -t iot-access "sensor device_id=sensor-temp-01 src_ip=192.168.2.50 dst_ip=10.0.0.5:8883 proto=MQTT"

# Unknown device
logger -t iot-access "camera src_ip=192.168.1.150 dst_ip=10.0.0.1:443 proto=HTTPS"
```

## Integration with IoT-Access-Sentinel

Once installed, these rules will:
1. Parse IoT device logs
2. Classify by device type
3. Check against network/time policies
4. Generate alerts with appropriate severity
5. Forward to IoT-Access-Sentinel API for LLM decision

The alert structure matches our `IoTAccessAlert` schema, making integration seamless.
