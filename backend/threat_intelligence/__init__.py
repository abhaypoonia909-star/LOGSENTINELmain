"""Threat Intelligence module for CyberShield AI.

Additive package providing MITRE ATT&CK mapping, OWASP Top 10 mapping,
threat timeline, attack statistics, recommendations, and export preparation.
Does not modify or depend on mutation of existing modules.
"""

from .service import ThreatIntelligenceService

__all__ = ["ThreatIntelligenceService"]