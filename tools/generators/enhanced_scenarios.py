#!/usr/bin/env python3
"""
Enhanced Synthetic Test Scenario Generator
===========================================
Generates comprehensive test scenarios focusing on areas where:
1. LLM excels (user auth, context, edge cases)
2. Baseline fails (no user checking, rigid rules)
"""

import json
import random
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List

# User database for realistic user auth scenarios
USERS = [
    {"user_id": "alice@company.com", "role": "security_admin", "devices": ["camera-office-01", "camera-office-02", "camera-lobby-01"]},
    {"user_id": "bob@company.com", "role": "security_staff", "devices": ["camera-lobby-01", "camera-parking-01"]},
    {"user_id": "security-system@company.com", "role": "system", "devices": ["*"]},  # Wildcard
    {"user_id": "charlie@company.com", "role": "facility_manager", "devices": ["lock-main-entrance", "lock-office-01"]},
]

# Device inventory
CAMERAS = [f"camera-office-{i:02d}" for i in range(1, 6)] + [f"camera-lobby-{i:02d}" for i in range(1, 4)] + ["camera-parking-01", "camera-warehouse-01"]
SENSORS = [f"sensor-temp-{i:02d}" for i in range(1, 6)] + [f"sensor-humidity-{i:02d}" for i in range(1, 4)]
LOCKS = ["lock-main-entrance", "lock-server-room", "lock-office-01", "lock-office-02"]

# Time windows
BUSINESS_HOURS = ("09:00", "17:00")
NIGHT_TIME = ("22:00", "06:00")

# Networks
ALLOWED_CAMERA_NET = "192.168.1.0/24"
ALLOWED_SENSOR_NET = "192.168.2.0/24"
ALLOWED_LOCK_NET = "192.168.3.0/24"
UNAUTHORIZED_NET = "172.16.0.0/16"


def random_ip_in_network(network: str) -> str:
    """Generate random IP in network (simplified)"""
    if network == "192.168.1.0/24":
        return f"192.168.1.{random.randint(1, 254)}"
    elif network == "192.168.2.0/24":
        return f"192.168.2.{random.randint(1, 254)}"
    elif network == "192.168.3.0/24":
        return f"192.168.3.{random.randint(1, 254)}"
    else:
        return f"172.16.{random.randint(1, 254)}.{random.randint(1, 254)}"


def generate_timestamp(hour: int, weekday: bool = True) -> str:
    """Generate timestamp"""
    day = random.randint(0, 4) if weekday else random.randint(5, 6)  # Mon-Fri or Sat-Sun
    dt = datetime(2025, 12, 22) + timedelta(days=day, hours=hour)
    return dt.isoformat() + "Z"


class ScenarioGenerator:
    """Generates diverse test scenarios"""
    
    def __init__(self, output_dir: str = "evaluation/synthetic"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.scenario_count = 0
    
    def save_scenario(self, scenario: Dict, name: str):
        """Save scenario to JSON file"""
        filepath = self.output_dir / f"{self.scenario_count:03d}_{name}.json"
        with open(filepath, 'w') as f:
            json.dump(scenario, f, indent=2)
        self.scenario_count += 1
        return filepath
    
    # ========== CATEGORY 1: User Authorization Scenarios ==========
    # These highlight LLM advantage - baseline has NO user checking
    
    def gen_valid_user_authorized_device(self, num: int = 10):
        """Valid user accessing authorized device - LLM SHOULD ALLOW, baseline might deny"""
        print(f"Generating {num} valid user + authorized device scenarios...")
        for i in range(num):
            user = random.choice(USERS[:2])  # alice or bob (not system)
            if user['devices'][0] != "*":
                device = random.choice(user['devices'])
            else:
                device = random.choice(CAMERAS)
            
            scenario = {
                "id": f"user-auth-valid-{i+1}",
                "timestamp": generate_timestamp(random.randint(9, 16)),  # Business hours
                "rule": {"level": 5, "description": "IoT camera access attempt", "id": "100010"},
                "device_id": device,
                "device_type": "camera",
                "source_ip": random_ip_in_network(ALLOWED_CAMERA_NET),
                "destination_ip": "10.0.0.1",
                "destination_port": 443,
                "protocol": "HTTPS",
                "user_id": user['user_id'],
                "auth_token": f"valid-token-{random.randint(1000, 9999)}",
                "user_role": user['role'],
                "expected_decision": "ALLOW",
                "description": f"{user['user_id']} accessing authorized {device}"
            }
            self.save_scenario(scenario, "user_auth_valid")
    
    def gen_valid_user_unauthorized_device(self, num: int = 10):
        """Valid user trying unauthorized device - BOTH SHOULD DENY but for different reasons"""
        print(f"Generating {num} valid user + unauthorized device scenarios...")
        for i in range(num):
            user = random.choice(USERS[:2])  # alice or bob
            # Pick a device NOT in their list
            all_cameras = set(CAMERAS)
            allowed = set(user['devices'])
            unauthorized = list(all_cameras - allowed)
            
            if unauthorized:
                device = random.choice(unauthorized)
                scenario = {
                    "id": f"user-auth-invalid-device-{i+1}",
                    "timestamp": generate_timestamp(random.randint(9, 16)),
                    "rule": {"level": 5, "description": "IoT camera access attempt", "id": "100010"},
                    "device_id": device,
                    "device_type": "camera",
                    "source_ip": random_ip_in_network(ALLOWED_CAMERA_NET),
                    "destination_ip": "10.0.0.1",
                    "destination_port": 443,
                    "protocol": "HTTPS",
                    "user_id": user['user_id'],
                    "auth_token": f"valid-token-{random.randint(1000, 9999)}",
                    "user_role": user['role'],
                    "expected_decision": "DENY",
                    "description": f"{user['user_id']} trying unauthorized {device}"
                }
                self.save_scenario(scenario, "user_auth_unauth_device")
    
    def gen_system_account_wildcard(self, num: int = 5):
        """System account with wildcard access - LLM handles, baseline might too"""
        print(f"Generating {num} system account wildcard scenarios...")
        for i in range(num):
            device = random.choice(CAMERAS + SENSORS)
            device_type = "camera" if "camera" in device else "sensor"
            net = ALLOWED_CAMERA_NET if device_type == "camera" else ALLOWED_SENSOR_NET
            
            scenario = {
                "id": f"system-wildcard-{i+1}",
                "timestamp": generate_timestamp(random.randint(0, 23)),  # Any time
                "rule": {"level": 5, "description": f"IoT {device_type} access attempt", "id": "100010"},
                "device_id": device,
                "device_type": device_type,
                "source_ip": random_ip_in_network(net),
                "destination_ip": "10.0.0.1",
                "destination_port": 443,
                "protocol": "HTTPS",
                "user_id": "security-system@company.com",
                "auth_token": "system-token-master",
                "user_role": "system",
                "expected_decision": "ALLOW",
                "description": "System account with wildcard access"
            }
            self.save_scenario(scenario, "system_wildcard")
    
    # ========== CATEGORY 2: Time/Network Edge Cases ==========
    # LLM can reason about context, baseline is rigid
    
    def gen_boundary_time_cases(self, num: int = 10):
        """Boundary times (e.g., 08:59, 17:01) - tests flexibility"""
        print(f"Generating {num} time boundary scenarios...")
        for i in range(num):
            # Half ALLOW (just inside), half DENY (just outside)
            if i % 2 == 0:
                hour = 9  # 09:00 - allowed
                expected = "ALLOW"
                desc = "exactly at start time"
            else:
                hour = 8  # 08:XX - before allowed
                expected = "DENY"
                desc = "just before allowed hours"
            
            user = random.choice(USERS[:2])
            device = random.choice(user['devices'] if user['devices'][0] != "*" else CAMERAS)
            
            scenario = {
                "id": f"time-boundary-{i+1}",
                "timestamp": generate_timestamp(hour),
                "rule": {"level": 5, "description": "IoT camera access attempt", "id": "100010"},
                "device_id": device,
                "device_type": "camera",
                "source_ip": random_ip_in_network(ALLOWED_CAMERA_NET),
                "destination_ip": "10.0.0.1",
                "destination_port": 443,
                "protocol": "HTTPS",
                "user_id": user['user_id'],
                "auth_token": f"valid-token-{random.randint(1000, 9999)}",
                "user_role": user['role'],
                "expected_decision": expected,
                "description": f"Camera access {desc}"
            }
            self.save_scenario(scenario, "time_boundary")
    
    def gen_weekend_violations(self, num: int = 5):
        """Weekend access attempts for weekday-only policies"""
        print(f"Generating {num} weekend violation scenarios...")
        for i in range(num):
            user = random.choice(USERS[:2])
            device = random.choice(user['devices'] if user['devices'][0] != "*" else CAMERAS)
            
            # Generate weekend timestamp
            weekday = False
            hour = random.randint(9, 16)  # During "business hours" but wrong day
            
            scenario = {
                "id": f"weekend-violation-{i+1}",
                "timestamp": generate_timestamp(hour, weekday=weekday),
                "rule": {"level": 5, "description": "IoT camera access attempt", "id": "100010"},
                "device_id": device,
                "device_type": "camera",
                "source_ip": random_ip_in_network(ALLOWED_CAMERA_NET),
                "destination_ip": "10.0.0.1",
                "destination_port": 443,
                "protocol": "HTTPS",
                "user_id": user['user_id'],
                "auth_token": f"valid-token-{random.randint(1000, 9999)}",
                "user_role": user['role'],
                "expected_decision": "DENY",
                "description": "Camera access on weekend (policy: weekdays only)"
            }
            self.save_scenario(scenario, "weekend_violation")
    
    # ========== CATEGORY 3: Sensors (No Auth Required) ==========
    # Tests flexibility - sensors don't need user auth
    
    def gen_sensor_valid(self, num: int = 10):
        """Sensors without user auth - BOTH should ALLOW"""
        print(f"Generating {num} valid sensor scenarios...")
        for i in range(num):
            device = random.choice(SENSORS)
            hour = random.randint(0, 23)  # 24/7 allowed
            
            scenario = {
                "id": f"sensor-valid-{i+1}",
                "timestamp": generate_timestamp(hour),
                "rule": {"level": 5, "description": "IoT sensor data transmission", "id": "100020"},
                "device_id": device,
                "device_type": "sensor",
                "source_ip": random_ip_in_network(ALLOWED_SENSOR_NET),
                "destination_ip": "10.0.0.2",
                "destination_port": 8883,
                "protocol": "MQTTS",
                "expected_decision": "ALLOW",
                "description": f"Sensor {device} transmitting data (no auth required)"
            }
            self.save_scenario(scenario, "sensor_valid")
    
    def gen_sensor_wrong_network(self, num: int = 5):
        """Sensors from wrong network - BOTH should DENY"""
        print(f"Generating {num} sensor network violation scenarios...")
        for i in range(num):
            device = random.choice(SENSORS)
            
            scenario = {
                "id": f"sensor-network-deny-{i+1}",
                "timestamp": generate_timestamp(random.randint(0, 23)),
                "rule": {"level": 5, "description": "IoT sensor data transmission", "id": "100020"},
                "device_id": device,
                "device_type": "sensor",
                "source_ip": random_ip_in_network(UNAUTHORIZED_NET),  # Wrong network
                "destination_ip": "10.0.0.2",
                "destination_port": 8883,
                "protocol": "MQTTS",
                "expected_decision": "DENY",
                "description": f"Sensor from unauthorized network"
            }
            self.save_scenario(scenario, "sensor_network_deny")
    
    # ========== CATEGORY 4: Adversarial/Attack Scenarios ==========
    
    def gen_missing_user_id_attacks(self, num: int = 5):
        """Missing user_id for auth-required devices - LLM catches, baseline might miss"""
        print(f"Generating {num} missing user_id scenarios...")
        for i in range(num):
            device = random.choice(CAMERAS)
            
            scenario = {
                "id": f"attack-no-userid-{i+1}",
                "timestamp": generate_timestamp(random.randint(9, 16)),
                "rule": {"level": 5, "description": "IoT camera access attempt", "id": "100010"},
                "device_id": device,
                "device_type": "camera",
                "source_ip": random_ip_in_network(ALLOWED_CAMERA_NET),
                "destination_ip": "10.0.0.1",
                "destination_port": 443,
                "protocol": "HTTPS",
                # user_id deliberately missing
                "expected_decision": "DENY",
                "description": "Camera access without user_id (auth required)"
            }
            self.save_scenario(scenario, "attack_no_userid")
    
    def gen_invalid_token_attacks(self, num: int = 5):
        """Invalid/expired tokens - LLM can validate, baseline blind"""
        print(f"Generating {num} invalid token scenarios...")
        invalid_tokens = ["expired", "invalid", "revoked", "malformed-###", ""]
        
        for i in range(num):
            user = random.choice(USERS[:2])
            device = random.choice(user['devices'] if user['devices'][0] != "*" else CAMERAS)
            
            scenario = {
                "id": f"attack-invalid-token-{i+1}",
                "timestamp": generate_timestamp(random.randint(9, 16)),
                "rule": {"level": 5, "description": "IoT camera access attempt", "id": "100010"},
                "device_id": device,
                "device_type": "camera",
                "source_ip": random_ip_in_network(ALLOWED_CAMERA_NET),
                "destination_ip": "10.0.0.1",
                "destination_port": 443,
                "protocol": "HTTPS",
                "user_id": user['user_id'],
                "auth_token": random.choice(invalid_tokens),
                "user_role": user['role'],
                "expected_decision": "DENY",
                "description": f"Valid user but invalid/expired token"
            }
            self.save_scenario(scenario, "attack_invalid_token")
    
    def generate_all(self):
        """Generate comprehensive test suite"""
        print("="*60)
        print("Generating Enhanced Synthetic Test Scenarios")
        print("="*60)
        
        # Category 1: User Authorization (LLM advantage)
        self.gen_valid_user_authorized_device(15)  # 15 ALLOW
        self.gen_valid_user_unauthorized_device(15)  # 15 DENY
        self.gen_system_account_wildcard(5)  # 5 ALLOW
        
        # Category 2: Time/Network Edge Cases
        self.gen_boundary_time_cases(10)  # 5 ALLOW, 5 DENY
        self.gen_weekend_violations(5)  # 5 DENY
        
        # Category 3: Sensors (flexibility test)
        self.gen_sensor_valid(10)  # 10 ALLOW
        self.gen_sensor_wrong_network(5)  # 5 DENY
        
        # Category 4: Attacks (security)
        self.gen_missing_user_id_attacks(10)  # 10 DENY
        self.gen_invalid_token_attacks(10)  # 10 DENY
        
        print("="*60)
        print(f"Total scenarios generated: {self.scenario_count}")
        print(f"Output directory: {self.output_dir}")
        print("="*60)
        
        # Summary
        print("\nExpected Distribution:")
        print(f"  ALLOW scenarios: ~45")
        print(f"  DENY scenarios: ~55")
        print(f"  Total: {self.scenario_count}")
        print("\nFocus Areas:")
        print("  - User authorization (LLM advantage)")
        print("  - Time/network edge cases (flexibility)")
        print("  - Device-specific auth requirements (context)")
        print("  - Security attacks (validation)")


if __name__ == "__main__":
    generator = ScenarioGenerator()
    generator.generate_all()
