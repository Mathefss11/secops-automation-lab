"""SOAR-style playbook: decide SAFE, SIMULATED response actions for an incident.

Nothing here performs a real action. There is no code path that calls a
firewall, EDR or identity API, runs a command, or changes the local system.
An action is a record of what a SOC *would* do, and ``simulated`` is always
True.

Two kinds of containment are kept apart:

- RECOMMEND_*  a suggestion that needs an analyst's approval
- SIMULATE_*   what an automated playbook would do. It is only chosen for
               CRITICAL risk with high detection confidence, and here it is
               only printed and exported.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from src.detection_engine import CREDENTIAL_ATTACK, PAYLOAD_EXECUTION, SUSPICIOUS_POWERSHELL, is_external_ip
from src.incident import Incident
from src.risk_engine import CRITICAL, HIGH, LOW, MEDIUM

RECORD_INCIDENT = "RECORD_INCIDENT"
ESCALATE_TO_ANALYST = "ESCALATE_TO_ANALYST"

# Containment kinds and how each is described.
IP_BLOCK = "IP_BLOCK"
ACCOUNT_DISABLE = "ACCOUNT_DISABLE"
ENDPOINT_ISOLATION = "ENDPOINT_ISOLATION"
CONTAINMENT_LABELS = {
    IP_BLOCK: "Block IP {target}",
    ACCOUNT_DISABLE: "Disable account {target}",
    ENDPOINT_ISOLATION: "Isolate host {target}",
}

# A false positive should never lead to (simulated) automatic containment, so
# automation also needs a high-confidence detection, not just a high score.
AUTO_CONTAINMENT_MIN_CONFIDENCE = 0.80


@dataclass(frozen=True)
class LevelPolicy:
    escalate: bool
    containment: str | None  # None, "RECOMMEND" or "SIMULATE"


PLAYBOOK_POLICY = {
    LOW: LevelPolicy(escalate=False, containment=None),
    MEDIUM: LevelPolicy(escalate=True, containment=None),
    HIGH: LevelPolicy(escalate=True, containment="RECOMMEND"),
    CRITICAL: LevelPolicy(escalate=True, containment="SIMULATE"),
}


@dataclass(frozen=True)
class PlaybookAction:
    action_type: str
    target: str
    reason: str
    # Not an __init__ argument: no action can be created as "real".
    simulated: bool = field(default=True, init=False)

    @property
    def requires_approval(self) -> bool:
        return self.action_type.startswith("RECOMMEND_")

    @property
    def description(self) -> str:
        if self.action_type == RECORD_INCIDENT:
            return f"Record incident {self.target}"
        if self.action_type == ESCALATE_TO_ANALYST:
            return f"Escalate {self.target} to an analyst"
        kind = self.action_type.split("_", 1)[1]
        return CONTAINMENT_LABELS[kind].format(target=self.target)

    def to_dict(self) -> dict[str, Any]:
        return {**asdict(self), "description": self.description, "requires_approval": self.requires_approval}


def containment_candidates(incident: Incident) -> list[tuple[str, str, str]]:
    """``(kind, target, reason)`` tuples suited to the affected entities.

    No account action without a known user, no isolation without a known host,
    and only external IPs are ever proposed for blocking.
    """
    detection = incident.detection
    candidates = []

    if detection.name == CREDENTIAL_ATTACK:
        if detection.user:
            candidates.append(
                (ACCOUNT_DISABLE, detection.user, f"account '{detection.user}' authenticated after a credential attack")
            )
        if is_external_ip(detection.source_ip):
            candidates.append((IP_BLOCK, detection.source_ip, "source of the repeated authentication failures"))

    elif detection.name in (SUSPICIOUS_POWERSHELL, PAYLOAD_EXECUTION):
        if detection.host:
            activity = "suspicious PowerShell chain" if detection.name == SUSPICIOUS_POWERSHELL else "payload execution"
            candidates.append((ENDPOINT_ISOLATION, detection.host, f"{activity} observed on this host"))
        for ip in detection.details.get("external_ips", []):
            if is_external_ip(ip):
                candidates.append((IP_BLOCK, ip, "external destination contacted by the executed code"))
    return candidates


def evaluate_playbook(incident: Incident) -> list[PlaybookAction]:
    """Deterministic actions for one incident, based on its risk level."""
    policy = PLAYBOOK_POLICY[incident.risk_level]
    context = f"{incident.risk_level} risk ({incident.risk_score}/100)"

    actions = [PlaybookAction(RECORD_INCIDENT, incident.incident_id, f"{context}: every incident is recorded")]
    if policy.escalate:
        actions.append(PlaybookAction(ESCALATE_TO_ANALYST, incident.incident_id, f"{context} needs analyst review"))

    mode = policy.containment
    confidence = incident.detection.confidence
    if mode == "SIMULATE" and confidence < AUTO_CONTAINMENT_MIN_CONFIDENCE:
        mode = "RECOMMEND"  # not confident enough to automate, even in simulation
    if mode is None:
        return actions

    for kind, target, why in containment_candidates(incident):
        if mode == "SIMULATE":
            reason = f"{context}, detection confidence {confidence:.2f}: {why}"
        else:
            reason = f"{context}: {why}; containment needs analyst approval"
        actions.append(PlaybookAction(f"{mode}_{kind}", target, reason))
    return actions


def run_playbooks(incidents: list[Incident]) -> list[Incident]:
    for incident in incidents:
        incident.playbook_actions = evaluate_playbook(incident)
    return incidents
