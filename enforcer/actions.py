"""
Enforcement Actions - IoT-Access-Sentinel Enforcer
Executes active response actions based on access control decisions
"""

from typing import Optional
from datetime import datetime

from config.settings import Settings
from common.schemas import EnforcementAction
from common.logging_config import get_logger
from observer.wazuh_connector import WazuhConnector

logger = get_logger(__name__)


class EnforcementActions:
    """
    Handles execution of enforcement actions (block IP, isolate device, etc.)
    """
    
    def __init__(self, settings: Settings, wazuh_connector: WazuhConnector):
        """
        Initialize enforcement actions handler
        
        Args:
            settings: Application settings
            wazuh_connector: Configured Wazuh connector
        """
        self.settings = settings
        self.wazuh_connector = wazuh_connector
        self.enabled = settings.enforcement_enabled
        
        logger.info(
            "enforcement_actions_initialized",
            enabled=self.enabled,
            dry_run=not self.enabled
        )
    
    async def execute(self, action: EnforcementAction) -> EnforcementAction:
        """
        Execute an enforcement action
        
        Args:
            action: Enforcement action to execute
        
        Returns:
            Updated enforcement action with execution results
        """
        if not self.enabled:
            logger.warning(
                "enforcement_dry_run",
                action_type=action.action_type,
                target=action.target,
                reason=action.reason
            )
            action.executed = False
            action.execution_result = "DRY RUN MODE - Action not executed"
            return action
        
        logger.info(
            "executing_enforcement_action",
            action_type=action.action_type,
            target=action.target
        )
        
        try:
            if action.action_type == "BLOCK_IP":
                result = await self._block_ip(
                    action.target,
                    action.duration,
                    agent_id=action.agent_id,
                    alert_id=action.alert_id
                )
            elif action.action_type == "ISOLATE_DEVICE":
                result = await self._isolate_device(
                    device_ip=action.target,
                    agent_id=action.agent_id,
                    alert_id=action.alert_id
                )
            elif action.action_type == "RATE_LIMIT":
                result = await self._rate_limit_device(
                    device_id=action.target,
                    device_ip=action.target,  # Pass the target IP
                    agent_id=action.agent_id,
                    alert_id=action.alert_id
                )
            elif action.action_type == "ALERT_ONLY":
                result = "Alert logged - no enforcement action taken"
            else:
                result = f"Unknown action type: {action.action_type}"
                logger.error("unknown_action_type", action_type=action.action_type)
            
            action.executed = True
            action.execution_result = result
            
            logger.info(
                "enforcement_action_executed",
                action_type=action.action_type,
                target=action.target,
                result=result
            )
            
        except Exception as e:
            logger.error(
                "enforcement_action_failed",
                action_type=action.action_type,
                target=action.target,
                error=str(e)
            )
            action.executed = False
            action.execution_result = f"Execution failed: {str(e)}"
        
        return action
    
    
    async def _block_ip(self, ip_address: str, duration: Optional[int] = None, agent_id: Optional[str] = None, alert_id: Optional[str] = None) -> str:
        """
        Block an IP address using Wazuh Active Response API.
        
        Sends firewall-drop command to the remote IoT device agent.
        
        Args:
            ip_address: IP address to block
            duration: Duration in seconds (default: 3600 = 1 hour)
            agent_id: Wazuh agent ID of the source device
            alert_id: Alert ID for tracking
        
        Returns:
            Execution result message
        """
        # Set default duration if not specified
        if duration is None:
            duration = 3600  # 1 hour default
        
        # Validate agent_id
        if not agent_id:
            logger.error("block_ip_no_agent_id", ip=ip_address)
            return f"Cannot block IP {ip_address}: No agent_id provided"
        
        try:
            # Send active response to Wazuh for remote execution
            # Command: firewall-drop
            # Arguments: ["-", "IP_ADDRESS"]
            # The "-" is for ADD action (vs "delete" for remove)
            
            response = await self.wazuh_connector.send_active_response(
                agent_id=agent_id,
                command="firewall-drop",
                arguments=["-", ip_address],  # "-" = add block rule
                alert_id=alert_id
            )
            
            logger.info(
                "wazuh_block_ip_sent",
                ip=ip_address,
                agent_id=agent_id,
                duration=duration,
                response=response
            )
            
            return (f"IP {ip_address} block command sent to agent {agent_id} via Wazuh Active Response "
                   f"(duration: {duration}s)")
        
        except Exception as e:
            logger.error(
                "wazuh_block_ip_failed",
                ip=ip_address,
                agent_id=agent_id,
                error=str(e)
            )
            return f"Failed to send block command to agent {agent_id}: {str(e)}"

    

    async def _isolate_device(self, device_ip: str, agent_id: Optional[str] = None, alert_id: Optional[str] = None) -> str:
        """
        Isolate a device by blocking its IP at the firewall/gateway level via Wazuh Active Response.
        
        Args:
            device_ip: IP address of the device to isolate
            agent_id: Wazuh agent ID of the source device (if known)
            alert_id: Alert ID for tracking
        
        Returns:
            Execution result message
        """
        if not agent_id:
            logger.error("isolate_device_no_agent_id", device_ip=device_ip)
            return f"Cannot isolate device {device_ip}: No agent_id provided"

        try:
            # Send active response to Wazuh for remote execution
            # Command: firewall-drop
            # Arguments: ["-", "IP_ADDRESS"]
            # This will block all traffic from/to the device's IP on the agent where the command is executed.
            # For true isolation, this command should ideally be sent to a gateway/firewall agent.
            
            response = await self.wazuh_connector.send_active_response(
                agent_id=agent_id, # This should ideally be the agent ID of the gateway/firewall
                command="firewall-drop",
                arguments=["-", device_ip],  # Drop traffic from this device IP
                alert_id=alert_id
            )
            
            logger.info(
                "wazuh_isolate_device_sent",
                device_ip=device_ip,
                agent_id=agent_id,
                response=response
            )
            
            return f"Device {device_ip} isolation command sent to agent {agent_id} via Wazuh Active Response."
                
        except Exception as e:
            logger.error(
                "wazuh_isolate_device_failed",
                device_ip=device_ip,
                agent_id=agent_id,
                error=str(e)
            )
            return f"Failed to send isolation command for device {device_ip} to agent {agent_id}: {str(e)}"
    
    async def _rate_limit_device(self, device_id: str, device_ip: str, agent_id: Optional[str] = None, alert_id: Optional[str] = None) -> str:
        """
        Apply rate limiting to a device
        
        Args:
            device_id: Device identifier
            device_ip: IP address of the device to rate limit
        
        Returns:
            Execution result message
        """
        if not agent_id:
             return f"Cannot rate limit device {device_id}: No agent_id provided"

        try:
            # Send active response to Wazuh for traffic shaping
            # Command: traffic-control (NOTE: This requires a custom script on the Wazuh agent)
            # This is a best-effort attempt to apply QOS/shaping
            
            response = await self.wazuh_connector.send_active_response(
                agent_id=agent_id,
                command="traffic-control", 
                arguments=["limit", device_ip, "1mbps"], # Example: limit to 1Mbps
                alert_id=alert_id
            )
            
            logger.info(
                "wazuh_rate_limit_sent",
                device_id=device_id,
                agent_id=agent_id,
                response=response
            )
            
            return f"Traffic shaping command sent for device {device_id} to agent {agent_id}"
            
        except Exception as e:
            # Fallback for now since traffic-control might not be installed
            logger.warning(
                "wazuh_rate_limit_failed", 
                device_id=device_id,
                error=str(e),
                message="Traffic shaping not available, falling back to logging only"
            )
            return f"Rate limiting not available for {device_id} (traffic-control script missing)"
