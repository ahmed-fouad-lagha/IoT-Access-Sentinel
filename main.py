"""
Main Application - IoT-Access-Sentinel
FastAPI webhook receiver for Wazuh IoT access alerts
Adapted from AI_SOC/main.py pattern

Workflow:
1. Receive IoT access alert from Wazuh (webhook or polling)
2. Analyze with Decision Engine (Policy + Context agents)
3. If DENY decision with high confidence, trigger Enforcer
4. Return enriched alert with decision and enforcement results
"""

from fastapi import FastAPI, HTTPException, status
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
from datetime import datetime
from typing import List

from config.settings import get_settings
from observer.wazuh_connector import WazuhConnector
from observer.models import IoTAccessAlert, EnrichedIoTAlert
from decision_engine.decision_pipeline import DecisionPipeline
from enforcer.actions import EnforcementActions
from common.logging_config import setup_logging, get_logger
from common.schemas import EnforcementAction

# Initialize settings and logging
settings = get_settings()
setup_logging(settings.log_level)
logger = get_logger(__name__)


# Lifespan context manager for startup/shutdown
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize clients and agents on startup"""
    logger.info(
        "service_startup",
        service=settings.service_name,
        version=settings.service_version
    )
    
    # Initialize components
    app.state.settings = settings
    app.state.wazuh_connector = WazuhConnector(settings)
    app.state.decision_pipeline = DecisionPipeline(settings)
    app.state.enforcement = EnforcementActions(settings)
    
    # Health checks
    wazuh_healthy = await app.state.wazuh_connector.health_check()
    logger.info("wazuh_health_check", healthy=wazuh_healthy)
    
    yield
    
    logger.info("service_shutdown")


# FastAPI application
app = FastAPI(
    title="IoT-Access-Sentinel",
    description="Autonomous Context-Aware Access Control for IoT via Multi-Agent Generative AI",
    version=settings.service_version,
    lifespan=lifespan
)


@app.post(
    "/access-control",
    response_model=EnrichedIoTAlert,
    status_code=status.HTTP_200_OK,
    summary="Process IoT access alert",
    description="""
    Primary webhook endpoint for Wazuh IoT access alerts.
    
    Workflow:
    1. Receive and validate alert
    2. Decision Engine analyzes with Policy + Context agents
    3. If DENY with high confidence, trigger enforcement
    4. Return enriched alert with decision and enforcement results
    """
)
async def process_access_alert(alert: IoTAccessAlert):
    """
    Process IoT access control alert
    
    Args:
        alert: IoT access alert from Wazuh
    
    Returns:
        Enriched alert with decision and enforcement information
    """
    logger.info(
        "access_alert_received",
        alert_id=alert.id,
        device_type=alert.device_type,
        source_ip=alert.source_ip,
        rule_level=alert.rule.level
    )
    
    try:
        # Step 1: Decision Engine Analysis
        decision_pipeline: DecisionPipeline = app.state.decision_pipeline
        decision = await decision_pipeline.make_decision(alert)
        
        logger.info(
            "decision_made",
            alert_id=alert.id,
            action=decision.action,
            confidence=decision.confidence,
            reason=decision.reason
        )
        
        # Step 2: Enforcement (if DENY and high confidence)
        enforcement_action = None
        enforcement_executed = False
        
        if decision.action == "DENY" and decision.confidence >= settings.min_decision_confidence:
            logger.info(
                "triggering_enforcement",
                alert_id=alert.id,
                confidence=decision.confidence,
                threshold=settings.min_decision_confidence
            )
            
            # Create enforcement action
            enforcement = EnforcementActions(app.state.settings)
            action = EnforcementAction(
                action_type="BLOCK_IP",  # Default to IP blocking
                target=alert.source_ip or "unknown",
                duration=3600,  # 1 hour block
                reason=decision.reason
            )
            
            # Execute enforcement
            executed_action = await enforcement.execute(action)
            enforcement_action = executed_action.action_type
            enforcement_executed = executed_action.executed
        
        # Step 3: Build enriched response
        enriched_alert = EnrichedIoTAlert(
            **alert.model_dump(),  # Include all original alert fields
            decision_action=decision.action,
            decision_confidence=decision.confidence,
            decision_reason=decision.reason,
            enforcement_action=enforcement_action,
            enforcement_executed=enforcement_executed,
            processing_timestamp=datetime.utcnow()
        )
        
        logger.info(
            "alert_processing_complete",
            alert_id=alert.id,
            decision=decision.action,
            enforced=enforcement_executed
        )
        
        return enriched_alert
        
    except Exception as e:
        logger.error(
            "alert_processing_failed",
            alert_id=alert.id,
            error=str(e),
            error_type=type(e).__name__
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Alert processing failed: {str(e)}"
        )


@app.get(
    "/alerts",
    summary="Fetch and analyze recent alerts",
    description="Query Wazuh for recent IoT access alerts and analyze them"
)
async def fetch_and_analyze_alerts(
    limit: int = 10,
    min_level: int = None,
    time_range: str = "1h"
):
    """
    Fetch alerts from Wazuh and analyze them
    
    Args:
        limit: Maximum alerts to fetch
        min_level: Minimum rule level
        time_range: Time range (1h, 24h, 7d)
    
    Returns:
        List of analyzed alerts
    """
    try:
        wazuh: WazuhConnector = app.state.wazuh_connector
        decision_pipeline: DecisionPipeline = app.state.decision_pipeline
        
        # Fetch raw alerts
        raw_alerts = await wazuh.get_iot_access_alerts(
            min_level=min_level,
            limit=limit,
            time_range=time_range
        )
        
        analyzed_alerts = []
        
        for raw_alert in raw_alerts:
            try:
                # Parse to IoTAccessAlert
                iot_alert = IoTAccessAlert(**raw_alert)
                
                # Analyze
                decision = await decision_pipeline.make_decision(iot_alert)
                
                analyzed_alerts.append({
                    "alert_id": iot_alert.id,
                    "device_type": iot_alert.device_type,
                    "source_ip": iot_alert.source_ip,
                    "rule_description": iot_alert.rule.description,
                    "decision": {
                        "action": decision.action,
                        "confidence": decision.confidence,
                        "reason": decision.reason,
                        "policy_matched": decision.policy_matched
                    }
                })
                
            except Exception as e:
                logger.error("alert_analysis_failed", alert=raw_alert, error=str(e))
                continue
        
        return {
            "total_fetched": len(raw_alerts),
            "total_analyzed": len(analyzed_alerts),
            "time_range": time_range,
            "alerts": analyzed_alerts
        }
        
    except Exception as e:
        logger.error("fetch_alerts_failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch alerts: {str(e)}"
        )


@app.get(
    "/health",
    summary="Service health check",
    description="Check health of IoT-Access-Sentinel and dependencies"
)
async def health_check():
    """Health check endpoint"""
    wazuh: WazuhConnector = app.state.wazuh_connector
    
    wazuh_healthy = await wazuh.health_check()
    overall_status = "healthy" if wazuh_healthy else "degraded"
    
    return {
        "status": overall_status,
        "service": settings.service_name,
        "version": settings.service_version,
        "timestamp": datetime.utcnow().isoformat(),
        "dependencies": {
            "wazuh_manager": wazuh_healthy,
            "decision_engine": True,  # Basic check - agents initialized
            "enforcement": settings.enforcement_enabled
        },
        "configuration": {
            "llm_provider": settings.llm_provider,
            "min_decision_confidence": settings.min_decision_confidence,
            "enforcement_enabled": settings.enforcement_enabled
        }
    }


@app.get("/", summary="Service information")
async def root():
    """Root endpoint with service information"""
    return {
        "service": settings.service_name,
        "version": settings.service_version,
        "description": "Autonomous Context-Aware Access Control for IoT via Multi-Agent Generative AI",
        "research_gap": "Access Management (M0801) - Active authorization enforcement using LLMs",
        "endpoints": {
            "access_control": "/access-control (POST) - Process IoT access alert",
            "alerts": "/alerts (GET) - Fetch and analyze recent alerts",
            "health": "/health (GET) - Health check",
            "docs": "/docs (GET) - API documentation"
        }
    }


if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "main:app",
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level,
        reload=True  # Enable hot reload for development
    )
