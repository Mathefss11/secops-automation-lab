"""Deterministic, explainable incident risk scoring (0-100).

Detection confidence and risk answer different questions:

- confidence: "How sure are we that this behavior matches the detection?"
- risk:       "How serious is the resulting incident, given the evidence and context?"

The score is the sum of four capped categories. Every point comes from a
``RiskContributor`` with a reason, so the score can always be explained.

| Category          | Max | Source                                                        |
|-------------------|-----|---------------------------------------------------------------|
| detection_evidence|  40 | detection confidence x 40                                     |
| observed_outcome  |  35 | the attack stage the evidence shows was reached               |
| related_activity  |  15 | another detection on the same host and user, close in time    |
| threat_intel      |  10 | best reputation among the incident's indicators (context only)|

Double counting is avoided on purpose. Launch-context signals (Office parent,
encoded command, hidden window, chmod, temp path) only count through
confidence. Outcome facts (account access, execution, outbound connection
after execution) are counted once, as impact, no matter how many signals
support them.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from typing import Any

from src.detection_engine import (
    CREDENTIAL_ATTACK,
    PAYLOAD_EXECUTION,
    SUSPICIOUS_POWERSHELL,
    Detection,
)
from src.enrichment import EnrichedDetection
from src.threat_intel import MALICIOUS, SUSPICIOUS, UNAVAILABLE

LOW = "LOW"
MEDIUM = "MEDIUM"
HIGH = "HIGH"
CRITICAL = "CRITICAL"

# Lower bound of each level (inclusive), highest first.
RISK_THRESHOLDS = ((CRITICAL, 80), (HIGH, 60), (MEDIUM, 40), (LOW, 0))

EVIDENCE_MAX_POINTS = 40
OUTCOME_MAX_POINTS = 35
RELATED_ACTIVITY_POINTS = 15
THREAT_INTEL_POINTS = {MALICIOUS: 10, SUSPICIOUS: 5}  # anything else: 0, never negative

# Outcome stages. Only the highest execution stage counts; an outbound
# connection after execution is added on top.
ACCOUNT_ACCESS_POINTS = 15
SCRIPT_EXECUTION_POINTS = 15
PAYLOAD_EXECUTION_POINTS = 25
EXTERNAL_AFTER_EXECUTION_POINTS = 10

RELATED_ACTIVITY_WINDOW = timedelta(minutes=60)


@dataclass(frozen=True)
class RiskContributor:
    category: str
    points: int
    reason: str


@dataclass
class RiskAssessment:
    score: int
    level: str
    contributors: list[RiskContributor]
    score_without_threat_intel: int
    level_note: str | None = None
    related_detection_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def risk_level(score: int) -> str:
    for level, minimum in RISK_THRESHOLDS:
        if score >= minimum:
            return level
    return LOW


# --- Category 1: detection evidence -------------------------------------------


def _evidence_contributor(detection: Detection) -> RiskContributor:
    points = round(detection.confidence * EVIDENCE_MAX_POINTS)
    return RiskContributor(
        "detection_evidence",
        points,
        f"detection confidence {detection.confidence:.2f} x {EVIDENCE_MAX_POINTS} "
        f"({len(detection.evidence)} correlated evidence events)",
    )


# --- Category 2: observed outcome -------------------------------------------


def _outcome_contributors(detection: Detection) -> list[RiskContributor]:
    """The furthest attack stage the detection's evidence actually shows."""
    details = detection.details
    contributors = []

    if detection.name == CREDENTIAL_ATTACK:
        contributors.append(
            RiskContributor(
                "observed_outcome",
                ACCOUNT_ACCESS_POINTS,
                f"successful authentication as '{detection.user}' after repeated failures (possible account access)",
            )
        )
    elif detection.name == PAYLOAD_EXECUTION:
        contributors.append(
            RiskContributor(
                "observed_outcome",
                PAYLOAD_EXECUTION_POINTS,
                f"downloaded file {details.get('downloaded_path')} was executed",
            )
        )
    elif detection.name == SUSPICIOUS_POWERSHELL:
        if details.get("executed_files"):
            contributors.append(
                RiskContributor(
                    "observed_outcome",
                    PAYLOAD_EXECUTION_POINTS,
                    f"file created by PowerShell was executed: {', '.join(details['executed_files'])}",
                )
            )
        else:
            contributors.append(
                RiskContributor("observed_outcome", SCRIPT_EXECUTION_POINTS, "suspicious PowerShell script executed")
            )

    if details.get("external_ips"):
        contributors.append(
            RiskContributor(
                "observed_outcome",
                EXTERNAL_AFTER_EXECUTION_POINTS,
                f"outbound connection to external IP(s) by the executed code: {', '.join(details['external_ips'])}",
            )
        )
    return _cap(contributors, OUTCOME_MAX_POINTS)


def _cap(contributors: list[RiskContributor], maximum: int) -> list[RiskContributor]:
    """Trim the last contributors so a category never exceeds its maximum."""
    capped, total = [], 0
    for contributor in contributors:
        points = min(contributor.points, maximum - total)
        if points > 0:
            capped.append(RiskContributor(contributor.category, points, contributor.reason))
            total += points
    return capped


# --- Category 3: related activity ---------------------------------------------


def _time(timestamp: str) -> datetime:
    return datetime.fromisoformat(timestamp.replace("Z", "+00:00"))


def find_related_detections(detection: Detection, all_detections: list[Detection]) -> list[Detection]:
    """Other detections on the same host for the same user, close in time.

    Related detections are referenced, not merged: each detection still gets
    its own incident.
    """
    if detection.host is None or detection.user is None:
        return []
    related = []
    for other in all_detections:
        if other.detection_id == detection.detection_id:
            continue
        if other.host != detection.host or other.user != detection.user:
            continue
        if abs(_time(other.first_seen) - _time(detection.first_seen)) <= RELATED_ACTIVITY_WINDOW:
            related.append(other)
    return related


def _related_contributor(detection: Detection, related: list[Detection]) -> RiskContributor | None:
    if not related:
        return None
    names = "; ".join(f"{other.name} ({other.detection_id})" for other in related)
    return RiskContributor(
        "related_activity",
        RELATED_ACTIVITY_POINTS,
        f"related detection on {detection.host} for user '{detection.user}' within "
        f"{int(RELATED_ACTIVITY_WINDOW.total_seconds() // 60)} minutes: {names}",
    )


# --- Category 4: threat intelligence (context only) -------------------------


def _threat_intel_contributor(enriched: EnrichedDetection) -> RiskContributor:
    results = [r for r in enriched.threat_intel if r.reputation != UNAVAILABLE]
    if not results:
        reason = "no threat intelligence available" if not enriched.threat_intel else "threat-intelligence lookups failed"
        return RiskContributor("threat_intel", 0, reason + "; risk relies on behavioral evidence only")

    best = max(results, key=lambda r: THREAT_INTEL_POINTS.get(r.reputation, 0))
    points = THREAT_INTEL_POINTS.get(best.reputation, 0)
    label = "simulated" if best.simulated else best.source
    if points == 0:
        return RiskContributor(
            "threat_intel",
            0,
            f"no indicator with negative reputation ({label}); absence of intelligence does not reduce risk",
        )
    return RiskContributor(
        "threat_intel",
        points,
        f"{best.indicator} has {best.reputation} reputation ({label} intelligence, context only)",
    )


# --- Assessment ---------------------------------------------------------------


def assess_risk(enriched: EnrichedDetection, related: list[Detection] | None = None) -> RiskAssessment:
    detection = enriched.detection
    related = related or []

    contributors = [_evidence_contributor(detection), *_outcome_contributors(detection)]
    related_contributor = _related_contributor(detection, related)
    if related_contributor:
        contributors.append(related_contributor)
    threat_intel = _threat_intel_contributor(enriched)
    contributors.append(threat_intel)

    score = max(0, min(100, sum(c.points for c in contributors)))
    score_without_ti = score - threat_intel.points
    level = risk_level(score)
    level_note = None
    # Policy: threat intelligence is context, so it may raise the score but
    # can never be the only reason an incident becomes CRITICAL.
    if level == CRITICAL and risk_level(score_without_ti) != CRITICAL:
        level = HIGH
        level_note = (
            f"capped at HIGH: without threat intelligence the score would be {score_without_ti}, "
            f"and threat intelligence alone cannot make an incident CRITICAL"
        )

    return RiskAssessment(
        score=score,
        level=level,
        contributors=contributors,
        score_without_threat_intel=score_without_ti,
        level_note=level_note,
        related_detection_ids=[other.detection_id for other in related],
    )
