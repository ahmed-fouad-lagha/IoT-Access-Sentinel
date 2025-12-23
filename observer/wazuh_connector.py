"""
Wazuh Connector - IoT-Access-Sentinel Observer
Handles authentication and API requests to Wazuh Manager
Adapted from AI_SOC/wazuh_client.py
"""

import httpx
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta

from config.settings import Settings
from common.logging_config import get_logger

logger = get_logger(__name__)


class WazuhConnector:
    """
    Client for Wazuh Manager REST API
    Adapted from AI_SOC pattern for IoT access alert monitoring
    """

    def __init__(self, settings: Settings):
        """
        Initialize Wazuh connector
        
        Args:
            settings: Application settings
        """
        self.settings = settings
        self.base_url = settings.wazuh_manager_url
        self.username = settings.wazuh_username
        self.password = settings.wazuh_password
        self.verify_ssl = settings.wazuh_verify_ssl

        self._token: Optional[str] = None
        self._token_expiry: Optional[datetime] = None

        logger.info(
            "wazuh_connector_initialized",
            manager_url=self.base_url,
            username=self.username,
            verify_ssl=self.verify_ssl
        )

    async def _authenticate(self) -> str:
        """
        Authenticate with Wazuh API and get JWT token
        Token is cached for 14 minutes (Wazuh tokens expire in 15 minutes)
        
        Returns:
            JWT token string
        
        Raises:
            httpx.HTTPError: If authentication fails
        """
        # Check if we have a valid cached token
        if self._token and self._token_expiry:
            if datetime.utcnow() < self._token_expiry:
                logger.debug("using_cached_token")
                return self._token

        auth_url = f"{self.base_url}/security/user/authenticate"

        try:
            async with httpx.AsyncClient(verify=self.verify_ssl) as client:
                response = await client.post(
                    auth_url,
                    auth=(self.username, self.password),
                    timeout=self.settings.wazuh_api_timeout
                )
                response.raise_for_status()

                data = response.json()
                self._token = data["data"]["token"]

                # Cache token for 14 minutes (safe margin before 15-minute expiry)
                self._token_expiry = datetime.utcnow() + timedelta(minutes=14)

                logger.info("wazuh_authentication_success")
                return self._token

        except httpx.HTTPError as e:
            logger.error(
                "wazuh_authentication_failed",
                error=str(e),
                url=auth_url
            )
            raise

    async def get_iot_access_alerts(
        self,
        min_level: Optional[int] = None,
        limit: int = 100,
        offset: int = 0,
        time_range: Optional[str] = "1h",
        device_type: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Fetch IoT access alerts from Wazuh Manager
        
        Args:
            min_level: Minimum rule level (uses config default if None)
            limit: Maximum number of alerts to return
            offset: Offset for pagination
            time_range: Time range (e.g., "1h", "24h", "7d")
            device_type: Filter by device type (optional)
        
        Returns:
            List of Wazuh alert dictionaries
        
        Raises:
            httpx.HTTPError: If API request fails
        """
        token = await self._authenticate()

        if min_level is None:
            min_level = self.settings.min_severity

        # Build query parameters
        params = {
            "limit": limit,
            "offset": offset,
            "rule.level": f">={min_level}",
            "sort": "-timestamp"  # Most recent first
        }

        if time_range:
            params["time_range"] = time_range
        
        # TODO: Add device_type filtering when custom Wazuh rules are configured
        # This will require custom decoders/rules that extract device_type from logs

        alerts_url = f"{self.base_url}/alerts"

        try:
            async with httpx.AsyncClient(verify=self.verify_ssl) as client:
                response = await client.get(
                    alerts_url,
                    headers={"Authorization": f"Bearer {token}"},
                    params=params,
                    timeout=self.settings.wazuh_api_timeout
                )
                response.raise_for_status()

                data = response.json()
                alerts = data.get("data", {}).get("affected_items", [])

                logger.info(
                    "iot_access_alerts_fetched",
                    count=len(alerts),
                    min_level=min_level,
                    time_range=time_range
                )

                return alerts

        except httpx.HTTPError as e:
            logger.error(
                "iot_access_alerts_fetch_failed",
                error=str(e),
                url=alerts_url
            )
            raise

    async def get_alert_by_id(self, alert_id: str) -> Optional[Dict[str, Any]]:
        """
        Fetch a specific alert by ID
        
        Args:
            alert_id: Wazuh alert ID
        
        Returns:
            Alert dictionary or None if not found
        
        Raises:
            httpx.HTTPError: If API request fails (except 404)
        """
        token = await self._authenticate()
        alert_url = f"{self.base_url}/alerts/{alert_id}"

        try:
            async with httpx.AsyncClient(verify=self.verify_ssl) as client:
                response = await client.get(
                    alert_url,
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=self.settings.wazuh_api_timeout
                )

                if response.status_code == 404:
                    logger.warning("alert_not_found", alert_id=alert_id)
                    return None

                response.raise_for_status()
                data = response.json()

                return data.get("data", {}).get("affected_items", [None])[0]

        except httpx.HTTPError as e:
            logger.error(
                "alert_fetch_by_id_failed",
                error=str(e),
                alert_id=alert_id
            )
            raise

    async def health_check(self) -> bool:
        """
        Check if Wazuh Manager API is accessible
        
        Returns:
            True if healthy, False otherwise
        """
        try:
            token = await self._authenticate()

            # Try basic API call
            async with httpx.AsyncClient(verify=self.verify_ssl) as client:
                response = await client.get(
                    f"{self.base_url}/?pretty=true",
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=self.settings.wazuh_api_timeout
                )
                response.raise_for_status()

                logger.info("wazuh_health_check_passed")
                return True

        except Exception as e:
            logger.error("wazuh_health_check_failed", error=str(e))
            return False
    
    async def send_active_response(
        self,
        agent_id: str,
        command: str = "firewall-drop",
        arguments: Optional[List[str]] = None,
        alert_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Send active response command to a specific Wazuh agent.
        
        This triggers enforcement actions on remote IoT devices via their Wazuh agents.
        
        Args:
            agent_id: Target agent ID (e.g., "00401")
            command: Active response command (default: "firewall-drop")
            arguments: Command arguments (e.g., ["-", "192.168.1.100"] for IP to block)
            alert_id: Associated alert ID for tracking
        
        Returns:
            API response dictionary
        
        Raises:
            httpx.HTTPError: If API request fails
            
        Example:
            # Block IP 192.168.1.100 on agent 00401
            await send_active_response(
                agent_id="00401",
                command="firewall-drop",
                arguments=["-", "192.168.1.100"]
            )
        """
        token = await self._authenticate()
        
        if arguments is None:
            arguments = []
        
        # Build active response payload
        payload = {
            "command": command,
            "arguments": arguments,
            "custom": False,  # Use built-in Wazuh command
            "alert": {
                "id": alert_id or "sentinel-enforcement"
            }
        }
        
        # Target specific agent
        active_response_url = f"{self.base_url}/active-response"
        params = {"agents_list": agent_id}
        
        try:
            async with httpx.AsyncClient(verify=self.verify_ssl) as client:
                response = await client.put(
                    active_response_url,
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Content-Type": "application/json"
                    },
                    json=payload,
                    params=params,
                    timeout=self.settings.wazuh_api_timeout
                )
                response.raise_for_status()
                
                data = response.json()
                
                logger.info(
                    "wazuh_active_response_sent",
                    agent_id=agent_id,
                    command=command,
                    arguments=arguments,
                    alert_id=alert_id
                )
                
                return data
        
        except httpx.HTTPError as e:
            logger.error(
                "wazuh_active_response_failed",
                agent_id=agent_id,
                command=command,
                error=str(e),
                url=active_response_url
            )
            raise
