"""
iptables IP Blocker - Real Enforcement Module
==============================================
Provides actual IP blocking using iptables DROP rules.

Features:
- Block IP addresses with configurable duration
- Auto-unblock after expiration
- Dry-run mode for safe testing
- Self-lockout prevention
- Audit logging

Security:
- Protected IPs (localhost, gateway) cannot be blocked
- Rate limiting on blocks
- Requires sudo permissions for iptables
"""

import subprocess
import threading
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Optional
from dataclasses import dataclass
from common.logging_config import get_logger

logger = get_logger(__name__)


@dataclass
class BlockedIP:
    """Represents a blocked IP address"""
    ip_address: str
    blocked_at: datetime
    expires_at: datetime
    reason: str
    alert_id: str
    status: str = 'active'  # 'active', 'expired', 'unblocked'


class IptablesBlocker:
    """
    Manages IP blocking using iptables.
    
    In dry-run mode, logs actions without executing them.
    In production mode, actually modifies iptables rules.
    """
    
    # IPs that should NEVER be blocked (prevent self-lockout)
    PROTECTED_IPS = [
        "127.0.0.1",
        "::1",
        "localhost",
        "192.168.1.1",  # Common gateway
        "10.0.0.1",     # Common gateway
    ]
    
    MAX_BLOCKS_PER_MINUTE = 100  # Rate limit
    
    def __init__(self, dry_run: bool = True):
        """
        Initialize iptables blocker.
        
        Args:
            dry_run: If True, only log actions without executing
        """
        self.dry_run = dry_run
        self.blocked_ips: Dict[str, BlockedIP] = {}
        self.block_count_this_minute = 0
        self.last_minute_reset = datetime.now(timezone.utc)
        self.unblock_timers: Dict[str, threading.Timer] = {}
        
        logger.info(
            "iptables_blocker_initialized",
            dry_run=dry_run,
            protected_ips=len(self.PROTECTED_IPS)
        )
    
    def _is_protected_ip(self, ip: str) -> bool:
        """Check if IP is in protected list"""
        return ip in self.PROTECTED_IPS
    
    def _check_rate_limit(self) -> bool:
        """Check if we're within rate limit for blocking"""
        now = datetime.now(timezone.utc)
        
        # Reset counter every minute
        if (now - self.last_minute_reset).seconds >= 60:
            self.block_count_this_minute = 0
            self.last_minute_reset = now
        
        if self.block_count_this_minute >= self.MAX_BLOCKS_PER_MINUTE:
            logger.warning(
                "block_rate_limit_exceeded",
                count=self.block_count_this_minute,
                limit=self.MAX_BLOCKS_PER_MINUTE
            )
            return False
        
        return True
    
    def _execute_iptables_command(self, args: List[str]) -> bool:
        """
        Execute an iptables command.
        
        Args:
            args: Command arguments (e.g., ["-I", "INPUT", "-s", "1.2.3.4", "-j", "DROP"])
        
        Returns:
            True if successful, False otherwise
        """
        if self.dry_run:
            logger.info("dry_run_iptables", command=" ".join(["sudo", "iptables"] + args))
            return True
        
        try:
            cmd = ["sudo", "iptables"] + args
            result = subprocess.run(
                cmd,
                check=True,
                capture_output=True,
                text=True,
                timeout=10
            )
            logger.debug("iptables_command_success", command=" ".join(cmd))
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(
                "iptables_command_failed",
                command=" ".join(cmd),
                error=e.stderr
            )
            return False
        except subprocess.TimeoutExpired:
            logger.error("iptables_command_timeout", command=" ".join(cmd))
            return False
    
    def block_ip(
        self,
        ip: str,
        duration: int = 3600,
        reason: str = "Access control violation",
        alert_id: str = "unknown"
    ) -> bool:
        """
        Block an IP address using iptables DROP rule.
        
        Args:
            ip: IP address to block
            duration: Block duration in seconds (default: 3600 = 1 hour)
            reason: Reason for blocking
            alert_id: Associated alert ID
        
        Returns:
            True if blocked successfully, False otherwise
        """
        # Safety checks
        if self._is_protected_ip(ip):
            logger.error(
                "block_refused_protected_ip",
                ip=ip,
                reason="IP is in protected list"
            )
            return False
        
        if not self._check_rate_limit():
            logger.error("block_refused_rate_limit", ip=ip)
            return False
        
        # Check if already blocked
        if ip in self.blocked_ips and self.blocked_ips[ip].status == 'active':
            logger.warning("ip_already_blocked", ip=ip)
            return True
        
        # Add iptables DROP rule
        success = self._execute_iptables_command([
            "-I", "INPUT",
            "-s", ip,
            "-j", "DROP"
        ])
        
        if not success:
            logger.error("failed_to_block_ip", ip=ip)
            return False
        
        # Record blocked IP
        blocked_at = datetime.now(timezone.utc)
        expires_at = blocked_at + timedelta(seconds=duration)
        
        blocked_ip = BlockedIP(
            ip_address=ip,
            blocked_at=blocked_at,
            expires_at=expires_at,
            reason=reason,
            alert_id=alert_id,
            status='active'
        )
        
        self.blocked_ips[ip] = blocked_ip
        self.block_count_this_minute += 1
        
        # Schedule auto-unblock
        timer = threading.Timer(duration, self._auto_unblock, args=[ip])
        timer.start()
        self.unblock_timers[ip] = timer
        
        logger.warning(
            "ip_blocked",
            ip=ip,
            duration=duration,
            expires_at=expires_at.isoformat(),
            reason=reason,
            alert_id=alert_id,
            dry_run=self.dry_run
        )
        
        return True
    
    def unblock_ip(self, ip: str) -> bool:
        """
        Unblock an IP address.
        
        Args:
            ip: IP address to unblock
        
        Returns:
            True if unblocked successfully, False otherwise
        """
        # Cancel auto-unblock timer if exists
        if ip in self.unblock_timers:
            self.unblock_timers[ip].cancel()
            del self.unblock_timers[ip]
        
        # Remove iptables rule
        success = self._execute_iptables_command([
            "-D", "INPUT",
            "-s", ip,
            "-j", "DROP"
        ])
        
        if not success:
            logger.error("failed_to_unblock_ip", ip=ip)
            return False
        
        # Update status
        if ip in self.blocked_ips:
            self.blocked_ips[ip].status = 'unblocked'
        
        logger.info(
            "ip_unblocked",
            ip=ip,
            dry_run=self.dry_run
        )
        
        return True
    
    def _auto_unblock(self, ip: str):
        """
        Automatically unblock an IP after expiration.
        Called by timer thread.
        
        Args:
            ip: IP address to unblock
        """
        logger.info("auto_unblock_triggered", ip=ip)
        
        if ip in self.blocked_ips:
            self.blocked_ips[ip].status = 'expired'
        
        self.unblock_ip(ip)
    
    def list_blocked_ips(self) -> List[BlockedIP]:
        """
        Get list of currently blocked IPs.
        
        Returns:
            List of BlockedIP objects
        """
        return [
            blocked_ip
            for blocked_ip in self.blocked_ips.values()
            if blocked_ip.status == 'active'
        ]
    
    def get_block_info(self, ip: str) -> Optional[BlockedIP]:
        """
        Get information about a blocked IP.
        
        Args:
            ip: IP address
        
        Returns:
            BlockedIP object if exists, None otherwise
        """
        return self.blocked_ips.get(ip)
    
    def cleanup_expired(self):
        """Remove expired block records from memory"""
        now = datetime.now(timezone.utc)
        expired = [
            ip for ip, block in self.blocked_ips.items()
            if block.expires_at < now and block.status != 'active'
        ]
        
        for ip in expired:
            del self.blocked_ips[ip]
        
        if expired:
            logger.info("cleaned_expired_blocks", count=len(expired))


# Singleton instance
_blocker_instance = None


def get_iptables_blocker(dry_run: bool = True) -> IptablesBlocker:
    """Get or create singleton blocker instance"""
    global _blocker_instance
    if _blocker_instance is None:
        _blocker_instance = IptablesBlocker(dry_run=dry_run)
    return _blocker_instance
