"""
Observer module for IoT-Access-Sentinel
Handles Wazuh integration and alert ingestion
"""

from .wazuh_connector import WazuhConnector
from .models import IoTAccessAlert

__all__ = ["WazuhConnector", "IoTAccessAlert"]
