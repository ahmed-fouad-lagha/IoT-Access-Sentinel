import pytest
from enforcement import get_iptables_blocker
from enforcer.actions import EnforcementActions
from config.settings import get_settings
from common.schemas import EnforcementAction
from observer.wazuh_connector import WazuhConnector


def test_ip_blocking_dry_run():
    """Verify IP blocking logic in dry-run mode"""
    blocker = get_iptables_blocker(dry_run=True)
    assert blocker.dry_run is True
    
    # 1. Block a test IP
    success = blocker.block_ip(
        ip="10.5.5.100",
        duration=60,
        reason="Test block",
        alert_id="test-001"
    )
    assert success is True
    
    # 2. List blocked IPs
    blocked = blocker.list_blocked_ips()
    assert len(blocked) == 1
    assert blocked[0].ip_address == "10.5.5.100"
    
    # 3. Try to block a protected IP (should be rejected/fail)
    success_protected = blocker.block_ip("127.0.0.1", duration=60)
    assert success_protected is False
    
    # 4. Unblock the test IP
    unblock_success = blocker.unblock_ip("10.5.5.100")
    assert unblock_success is True
    
    blocked_after = blocker.list_blocked_ips()
    assert len(blocked_after) == 0


@pytest.mark.asyncio
async def test_enforcement_actions():
    """Verify full enforcement actions execution pipeline"""
    settings = get_settings()
    connector = WazuhConnector(settings)
    ea = EnforcementActions(settings, connector)
    
    # Test action block trigger
    action = EnforcementAction(
        action_type="BLOCK_IP",
        target="10.5.5.200",
        duration=120,
        reason="Test enforcement action",
        agent_id="001",
        alert_id="test-002"
    )
    result = await ea.execute(action)
    
    assert result.executed is True
    assert "block command" in result.execution_result.lower()
