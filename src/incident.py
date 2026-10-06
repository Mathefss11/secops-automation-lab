"""Incidents: the decision context built around one enriched detection.

An ``Incident`` wraps (does not copy) the EnrichedDetection and adds the risk
assessment and the playbook actions. Each detection becomes its own incident.
Related detections are referenced by ID but not merged.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

from src.detection_engine import CREDENTIAL_ATTACK, PAYLOAD_EXECUTION, SUSPICIOUS_POWERSHELL, Detection
from src.enrichment import EnrichedDetection
from src.risk_engine import RiskAssessment, assess_risk, find_related_detections

INCIDENT_TITLES = {
    CREDENTIAL_ATTACK: "Possible Credential Compromise",
    SUSPICIOUS_POWERSHELL: "Possible Endpoint Compromise via Suspicious PowerShell",
    PAYLOAD_EXECUTION: "Possible Payload Execution on Linux Host",
}

SIMULATION_DISCLAIMER = (
    "All playbook actions are simulated. No firewall, endpoint, account or other real system was changed."
)


@dataclass
class Incident:
    incident_id: str
    title: str
    created_at: str
    enriched_detection: EnrichedDetection
    risk: RiskAssessment
    playbook_actions: list = field(default_factory=list)  # list[PlaybookAction], set by src.playbook

    @property
    def detection(self) -> Detection:
        return self.enriched_detection.detection

    @property
    def severity(self) -> str:
        """Detection severity (how strong the detection is), not incident risk."""
        return self.detection.severity

    @property
    def risk_score(self) -> int:
        return self.risk.score

    @property
    def risk_level(self) -> str:
        return self.risk.level

    @property
    def risk_contributors(self) -> list:
        return self.risk.contributors

    @property
    def recommendations(self) -> list:
        """Actions that need an analyst's decision."""
        return [action for action in self.playbook_actions if action.action_type.startswith("RECOMMEND_")]

    def to_report(self) -> dict[str, Any]:
        """Analyst-friendly JSON structure for the incident report."""
        detection = self.detection
        enriched = self.enriched_detection
        return {
            "incident_id": self.incident_id,
            "title": self.title,
            "created_at": self.created_at,
            "risk": {
                "score": self.risk.score,
                "level": self.risk.level,
                "level_note": self.risk.level_note,
                "score_without_threat_intel": self.risk.score_without_threat_intel,
                "contributors": [
                    {"points": c.points, "category": c.category, "reason": c.reason} for c in self.risk.contributors
                ],
            },
            "detection": {
                "detection_id": detection.detection_id,
                "name": detection.name,
                "severity": detection.severity,
                "confidence": detection.confidence,
                "host": detection.host,
                "user": detection.user,
                "source_ip": detection.source_ip,
                "first_seen": detection.first_seen,
                "last_seen": detection.last_seen,
                "reasoning": detection.reasoning,
                "signals": detection.signals,
                "evidence": [
                    {"event_id": e.event_id, "timestamp": e.timestamp, "description": e.description}
                    for e in detection.evidence
                ],
                "false_positives": detection.false_positives,
                "details": detection.details,
            },
            "related_detections": self.risk.related_detection_ids,
            "mitre_attack": [technique.to_dict() for technique in enriched.mitre_techniques],
            "threat_intel": [result.to_dict() for result in enriched.threat_intel],
            "threat_intel_status": enriched.threat_intel_status,
            "recommendations": [action.to_dict() for action in self.recommendations],
            "playbook_actions": [action.to_dict() for action in self.playbook_actions],
            "simulated_response": True,
            "disclaimer": SIMULATION_DISCLAIMER,
        }


def incident_id_for(detection: Detection) -> str:
    """Deterministic: the same detection always gives the same incident ID."""
    return "INC-" + hashlib.sha256(detection.detection_id.encode()).hexdigest()[:10]


def create_incidents(enriched_detections: list[EnrichedDetection]) -> list[Incident]:
    """One incident per enriched detection, with risk assessed in the context
    of the other detections from the same run. Highest risk first."""
    all_detections = [enriched.detection for enriched in enriched_detections]
    incidents = []
    for enriched in enriched_detections:
        detection = enriched.detection
        related = find_related_detections(detection, all_detections)
        incidents.append(
            Incident(
                incident_id=incident_id_for(detection),
                title=INCIDENT_TITLES.get(detection.name, detection.name),
                # Simulation time: the incident is opened when its last evidence
                # event is observed. This keeps reports reproducible.
                created_at=detection.last_seen,
                enriched_detection=enriched,
                risk=assess_risk(enriched, related),
            )
        )
    return sorted(incidents, key=lambda incident: (-incident.risk_score, incident.created_at))
