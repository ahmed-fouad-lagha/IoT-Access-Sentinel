"""
Baseline package - Traditional static firewall for comparison
"""

from .static_firewall import StaticFirewall, get_static_firewall

__all__ = ['StaticFirewall', 'get_static_firewall']
