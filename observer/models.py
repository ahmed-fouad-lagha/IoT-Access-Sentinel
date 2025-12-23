"""
Alert Models - IoT-Access-Sentinel Observer
Pydantic models for Wazuh IoT access alerts
"""

from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from datetime import datetime


class WazuhRule(BaseModel):
    """Wazuh rule information"""
    level: int = Field(..., description="Rule severity level (0-15)")
    description: str = Field(..., description="Rule description")
    id: Optional[str] = Field(None, description="Rule ID")
    mitre: Optional[Dict[str, Any]] = Field(None, description="MITRE ATT&CK mapping")
    groups: Optional[List[str]] = Field(None, description="Rule groups")


class IoTAccessAlert(BaseModel):
    """
    IoT Access Alert from Wazuh
    Represents a network access attempt by an IoT device
    """
    
    # Wazuh Alert Fields
    id: str = Field(..., description="Wazuh alert ID")
    timestamp: str = Field(..., description="Alert timestamp")
    rule: WazuhRule = Field(..., description="Triggered rule")
    
    # IoT-Specific Fields
    device_id: Optional[str] = Field(None, description="IoT device identifier")
    device_type: Optional[str] = Field(None, description="Device type (camera, sensor, etc.)")
    source_ip: Optional[str] = Field(None, description="Source IP address")
    destination_ip: Optional[str] = Field(None, description="Destination IP")
    destination_port: Optional[int] = Field(None, description="Destination port")
    protocol: Optional[str] = Field(None, description="Network protocol")
    
    # Additional Context
    agent_id: Optional[str] = Field(None, description="Wazuh agent ID")
    agent_name: Optional[str] = Field(None, description="Wazuh agent name")
    location: Optional[str] = Field(None, description="Alert location/source")
    
    # Raw data
    full_log: Optional[str] = Field(None, description="Full log message")
    data: Optional[Dict[str, Any]] = Field(None, description="Additional alert data")
    
    class Config:
        # Allow extra fields from Wazuh that we might not explicitly model
        extra = "allow"


class EnrichedIoTAlert(IoTAccessAlert):
    """
    Enriched IoT alert with decision and enforcement information
    """
    
    decision_action: Optional[str] = Field(None, description="Access decision (ALLOW/DENY)")
    decision_confidence: Optional[float] = Field(None, description="Decision confidence")
    decision_reason: Optional[str] = Field(None, description="Reason for decision")
    enforcement_action: Optional[str] = Field(None, description="Type of enforcement action taken")
    enforcement_executed: Optional[bool] = Field(None, description="Whether enforcement was executed")
    processing_timestamp: Optional[datetime] = Field(None, description="When alert was processed")
