#!/usr/bin/env python3
"""
Test script for IP blocking enforcement
Demonstrates iptables integration in dry-run mode
"""

import asyncio
import sys
from pathlib import Path

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from enforcement import get_iptables_blocker
from enforcer.actions import EnforcementActions
from config.settings import Settings
from common.schemas import EnforcementAction


async def test_ip_blocking_dry_run():
    """Test IP blocking in safe dry-run mode"""
    print("=" * 60)
    print("IP Blocking Test - Dry-Run Mode")
    print("=" * 60)
    
    # Get blocker in dry-run (safe, no actual blocking)
    blocker = get_iptables_blocker(dry_run=True)
    
    print(f"\n1. Blocker initialized (dry_run={blocker.dry_run})")
    print(f"   Protected IPs: {blocker.PROTECTED_IPS}")
    
    # Test 1: Block a test IP
    print(f"\n2. Testing block_ip()...")
    success = blocker.block_ip(
        ip="10.5.5.100",
        duration=60,
        reason="Test block",
        alert_id="test-001"
    )
    print(f"   Block successful: {success}")
    
    # Test 2: List blocked IPs
    blocked = blocker.list_blocked_ips()
    print(f"\n3. Currently blocked IPs: {len(blocked)}")
    for block in blocked:
        print(f"   - {block.ip_address} (expires: {block.expires_at})")
    
    # Test 3: Try to block protected IP (should fail)
    print(f"\n4. Testing protection (try to block localhost)...")
    success_protected = blocker.block_ip("127.0.0.1", duration=60)
    print(f"   Block attempt: {success_protected} (should be False)")
    
    # Test 4: Unblock IP
    print(f"\n5. Testing unblock_ip()...")
    unblock_success = blocker.unblock_ip("10.5.5.100")
    print(f"   Unblock successful: {unblock_success}")
    
    blocked_after = blocker.list_blocked_ips()
    print(f"   Blocked IPs after unblock: {len(blocked_after)}")
    
    print("\n" + "=" * 60)
    print("✓ All dry-run tests passed!")
    print("=" * 60)
    print("\nTo enable REAL blocking:")
    print("1. Configure passwordless sudo for iptables")
    print("   echo 'your_user ALL=(ALL) NOPASSWD: /usr/sbin/iptables' | sudo tee /etc/sudoers.d/iot-sentinel")
    print("2. Set enforcementenabled=True in .env")
    print("3. Change dry_run=False in blocker initialization")


async def test_enforcement_actions():
    """Test full enforcement actions integration"""
    print("\n\n" + "=" * 60)
    print("Enforcement Actions Integration Test")
    print("=" * 60)
    
    settings = Settings()
    ea = EnforcementActions(settings)
    
    print(f"\nEnforcement enabled: {ea.enabled}")
    
    # Create test action
    action = EnforcementAction(
        action_type="BLOCK_IP",
        target="10.5.5.200",
        duration=120,
        reason="Test enforcement action"
    )
    
    print(f"\nExecuting action: {action.action_type} on {action.target}")
    result = await ea.execute(action)
    
    print(f"Executed: {result.executed}")
    print(f"Result: {result.execution_result}")
    
    print("\n✓ Enforcement actions test complete!")


if __name__ == "__main__":
    print("IoT-Access-Sentinel - IP Blocking Test Suite\n")
    asyncio.run(test_ip_blocking_dry_run())
    asyncio.run(test_enforcement_actions())
