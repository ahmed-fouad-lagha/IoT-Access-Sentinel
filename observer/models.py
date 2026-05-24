"""
Alert Models - IoT-Access-Sentinel Observer
Pydantic models for Wazuh IoT access alerts
"""

from pydantic import BaseModel, Field, field_validator, model_validator, ConfigDict
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
    
    # User Authorization Fields (M0801 - User Identification & Verification)
    user_id: Optional[str] = Field(None, description="User identifier (email/username)")
    auth_token: Optional[str] = Field(None, description="Authentication token status (valid/invalid/missing)")
    user_role: Optional[str] = Field(None, description="User role (admin/security_staff/viewer)")
    session_id: Optional[str] = Field(None, description="User session identifier")
    expected_decision: Optional[str] = Field(None, description="Expected decision for testing/evaluation")
    
    # Additional Context
    agent_id: Optional[str] = Field(None, description="Wazuh agent ID (source device)")
    agent_name: Optional[str] = Field(None, description="Wazuh agent name (source device)")
    location: Optional[str] = Field(None, description="Alert location/source")
    
    # Raw data
    full_log: Optional[str] = Field(None, description="Full log message")
    data: Optional[Dict[str, Any]] = Field(None, description="Additional alert data")
    
    @field_validator('agent_id', 'agent_name', mode='before')
    @classmethod
    def extract_agent_fields(cls, v, info):
        """
        Extract agent ID and name from nested Wazuh JSON structure.
        
        Wazuh sends:
          {
            "agent": {"id": "00401", "name": "iot-device-01"},
            "manager": {...}
          }
        
        We need agent.id (source device), NOT manager info.
        """
        # If value already provided directly, use it
        if v is not None:
            return v
        
        # Try to extract from 'agent' nested object in data
        # Access the full data context from validation
        field_name = info.field_name
        
        # Check if we have the raw agent object
        # This will be handled by Pydantic's data dict
        return v  # Return as-is; will be handled by model_validator
    
    @model_validator(mode='before')
    @classmethod
    def extract_nested_agent_info(cls, data):
        """
        Pre-process Wazuh alert to extract nested agent information.
        
        Wazuh alert structure:
          {
            "id": "...",
            "agent": {
              "id": "00401",        ← Extract this
              "name": "device-01"   ← Extract this
            },
            "manager": {...},       ← Ignore this
            ...
          }
        """
        if isinstance(data, dict):
            # Extract agent.id if present in nested structure
            if 'agent' in data and isinstance(data['agent'], dict):
                if 'agent_id' not in data or data['agent_id'] is None:
                    data['agent_id'] = data['agent'].get('id')
                
                if 'agent_name' not in data or data['agent_name'] is None:
                    data['agent_name'] = data['agent'].get('name')
        
        return data
    
    model_config = ConfigDict(extra="allow")


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
