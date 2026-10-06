"""Combine a Detection with ATT&CK mappings and threat intelligence.

Composition, not mutation: ``EnrichedDetection`` wraps the original Detection,
which is left unchanged. Enrichment adds context; it never changes a
detection's severity or confidence (incident risk is scored in src/risk_engine.py).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from src.detection_engine import Detection, is_external_ip
from src.mitre import AttackTechnique, map_detection
from src.threat_intel import CachedThreatIntel, ThreatIntelResult


@dataclass
class EnrichedDetection:
    detection: Detection
    mitre_techniques: list[AttackTechnique] = field(default_factory=list)
    threat_intel: list[ThreatIntelResult] = field(default_factory=list)
    threat_intel_status: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Detection fields stay at the top level (as in the previous export
        format); enrichment is added under its own keys."""
        return {
            **self.detection.to_dict(),
            "mitre_attack": [technique.to_dict() for technique in self.mitre_techniques],
            "threat_intel": [result.to_dict() for result in self.threat_intel],
            "threat_intel_status": self.threat_intel_status,
        }


def indicators_for(detection: Detection) -> list[str]:
    """External IPs worth enriching: the source of a credential attack, and
    external destinations contacted by the PowerShell or payload processes."""
    candidates = [detection.source_ip] + list(detection.details.get("external_ips", []))
    indicators: list[str] = []
    for ip in candidates:
        if is_external_ip(ip) and ip not in indicators:
            indicators.append(ip)
    return indicators


def enrich_detection(
    detection: Detection, intel: CachedThreatIntel | None, disabled_reason: str | None = None
) -> EnrichedDetection:
    """Add ATT&CK techniques and, if ``intel`` is given, threat intelligence.

    With ``intel=None`` no lookup is attempted and ``disabled_reason`` explains why.
    """
    indicators = indicators_for(detection)
    if intel is None:
        results: list[ThreatIntelResult] = []
        status = f"not queried: {disabled_reason or 'threat intelligence disabled'}"
    else:
        results = [intel.lookup_ip(ip) for ip in indicators]
        status = f"looked up {len(indicators)} indicator(s) with {intel.provider.name}"
        if intel.provider.simulated:
            status += " - SIMULATED data, not real intelligence"
    return EnrichedDetection(detection, map_detection(detection), results, status)


def enrich_detections(
    detections: list[Detection], intel: CachedThreatIntel | None, disabled_reason: str | None = None
) -> list[EnrichedDetection]:
    return [enrich_detection(detection, intel, disabled_reason) for detection in detections]
