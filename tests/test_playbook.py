import ast
import dataclasses
import json
from pathlib import Path

import pytest

from src import playbook
from src.detection_engine import CREDENTIAL_ATTACK, PAYLOAD_EXECUTION, SUSPICIOUS_POWERSHELL, Detection, Evidence
from src.enrichment import EnrichedDetection
from src.incident import Incident
from src.playbook import (
    AUTO_CONTAINMENT_MIN_CONFIDENCE,
    ESCALATE_TO_ANALYST,
    RECORD_INCIDENT,
    PlaybookAction,
    evaluate_playbook,
)
from src.risk_engine import CRITICAL, HIGH, LOW, MEDIUM, RiskAssessment

SRC_DIR = Path(__file__).resolve().parent.parent / "src"


def make_incident(name, level, confidence=0.95, host="host-01", user="deploy", source_ip=None, external_ips=()):
    detection = Detection(
        detection_id="DET-test000001",
        name=name,
        description="test",
        severity=HIGH,
        confidence=confidence,
        first_seen="2026-09-14T09:00:00.000Z",
        last_seen="2026-09-14T09:00:00.000Z",
        host=host,
        user=user,
        source_ip=source_ip,
        reasoning="test",
        signals=[],
        evidence=[Evidence("evt-1", "2026-09-14T09:00:00.000Z", "test")],
        details={"external_ips": list(external_ips)},
    )
    scores = {LOW: 20, MEDIUM: 50, HIGH: 70, CRITICAL: 90}
    risk = RiskAssessment(scores[level], level, [], scores[level])
    return Incident("INC-test", "test", detection.last_seen, EnrichedDetection(detection), risk)


def action_types(actions):
    return [action.action_type for action in actions]


def targets(actions, action_type):
    return [action.target for action in actions if action.action_type == action_type]


# --- Policy by risk level ---------------------------------------------------------


def test_low_only_records():
    actions = evaluate_playbook(make_incident(CREDENTIAL_ATTACK, LOW, source_ip="203.0.113.5"))
    assert action_types(actions) == [RECORD_INCIDENT]


def test_medium_escalates_without_containment():
    actions = evaluate_playbook(make_incident(CREDENTIAL_ATTACK, MEDIUM, source_ip="203.0.113.5"))
    assert action_types(actions) == [RECORD_INCIDENT, ESCALATE_TO_ANALYST]


def test_high_recommends_containment_only():
    actions = evaluate_playbook(make_incident(CREDENTIAL_ATTACK, HIGH, source_ip="203.0.113.5"))
    containment = action_types(actions)[2:]
    assert containment == ["RECOMMEND_ACCOUNT_DISABLE", "RECOMMEND_IP_BLOCK"]
    assert all(action.requires_approval for action in actions[2:])
    assert not any(t.startswith("SIMULATE_") for t in action_types(actions))


def test_critical_simulates_containment():
    actions = evaluate_playbook(make_incident(PAYLOAD_EXECUTION, CRITICAL, external_ips=["198.51.100.9"]))
    assert action_types(actions) == [
        RECORD_INCIDENT,
        ESCALATE_TO_ANALYST,
        "SIMULATE_ENDPOINT_ISOLATION",
        "SIMULATE_IP_BLOCK",
    ]


def test_critical_with_lower_confidence_only_recommends():
    incident = make_incident(PAYLOAD_EXECUTION, CRITICAL, confidence=AUTO_CONTAINMENT_MIN_CONFIDENCE - 0.05)
    types = action_types(evaluate_playbook(incident))
    assert "RECOMMEND_ENDPOINT_ISOLATION" in types
    assert not any(t.startswith("SIMULATE_") for t in types)


# --- Targets match the affected entities ----------------------------------------


def test_credential_incident_targets_user_and_source_ip():
    actions = evaluate_playbook(make_incident(CREDENTIAL_ATTACK, HIGH, user="deploy", source_ip="203.0.113.45"))
    assert targets(actions, "RECOMMEND_ACCOUNT_DISABLE") == ["deploy"]
    assert targets(actions, "RECOMMEND_IP_BLOCK") == ["203.0.113.45"]
    assert "RECOMMEND_ENDPOINT_ISOLATION" not in action_types(actions)


def test_internal_source_ip_is_never_blocked():
    actions = evaluate_playbook(make_incident(CREDENTIAL_ATTACK, CRITICAL, source_ip="10.0.5.23"))
    assert not any(t.endswith("_IP_BLOCK") for t in action_types(actions))


def test_powershell_incident_targets_host():
    actions = evaluate_playbook(make_incident(SUSPICIOUS_POWERSHELL, HIGH, host="FIN-WS-07"))
    assert targets(actions, "RECOMMEND_ENDPOINT_ISOLATION") == ["FIN-WS-07"]
    assert "RECOMMEND_ACCOUNT_DISABLE" not in action_types(actions)


def test_payload_incident_targets_host_and_external_destinations():
    incident = make_incident(PAYLOAD_EXECUTION, CRITICAL, host="web-01", external_ips=["198.51.100.9", "10.0.0.8"])
    actions = evaluate_playbook(incident)
    assert targets(actions, "SIMULATE_ENDPOINT_ISOLATION") == ["web-01"]
    assert targets(actions, "SIMULATE_IP_BLOCK") == ["198.51.100.9"]  # internal IP excluded


def test_missing_user_gives_no_account_action():
    actions = evaluate_playbook(make_incident(CREDENTIAL_ATTACK, CRITICAL, user=None, source_ip="203.0.113.45"))
    assert not any("ACCOUNT_DISABLE" in t for t in action_types(actions))
    assert targets(actions, "SIMULATE_IP_BLOCK") == ["203.0.113.45"]


def test_missing_host_gives_no_isolation_action():
    for name in (SUSPICIOUS_POWERSHELL, PAYLOAD_EXECUTION):
        actions = evaluate_playbook(make_incident(name, CRITICAL, host=None))
        assert not any("ENDPOINT_ISOLATION" in t for t in action_types(actions))


# --- Everything is simulated ------------------------------------------------------


def test_every_action_is_marked_simulated():
    for name in (CREDENTIAL_ATTACK, SUSPICIOUS_POWERSHELL, PAYLOAD_EXECUTION):
        for level in (LOW, MEDIUM, HIGH, CRITICAL):
            incident = make_incident(name, level, source_ip="203.0.113.45", external_ips=["198.51.100.9"])
            for action in evaluate_playbook(incident):
                assert action.simulated is True
                assert action.to_dict()["simulated"] is True


def test_a_non_simulated_action_cannot_be_created():
    with pytest.raises(TypeError):
        PlaybookAction("SIMULATE_IP_BLOCK", "203.0.113.45", "test", simulated=False)


def test_simulated_flag_cannot_be_changed():
    action = PlaybookAction("SIMULATE_IP_BLOCK", "203.0.113.45", "test")
    with pytest.raises(dataclasses.FrozenInstanceError):
        action.simulated = False


def test_response_modules_have_no_system_or_network_capabilities():
    """Static check: the risk, incident and playbook code imports nothing that
    could run commands, open connections or change the operating system."""
    forbidden = {"subprocess", "os", "socket", "requests", "urllib", "http", "shutil", "ctypes", "winreg"}
    for module in ("playbook.py", "risk_engine.py", "incident.py"):
        tree = ast.parse((SRC_DIR / module).read_text(encoding="utf-8"))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported |= {alias.name.split(".")[0] for alias in node.names}
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        assert imported.isdisjoint(forbidden), (module, imported & forbidden)


def test_actions_serialize_to_json():
    incident = make_incident(PAYLOAD_EXECUTION, CRITICAL, external_ips=["198.51.100.9"])
    exported = json.loads(json.dumps([a.to_dict() for a in evaluate_playbook(incident)]))
    assert exported[2]["description"] == "Isolate host host-01"
    assert exported[2]["requires_approval"] is False


def test_policy_covers_every_level():
    assert set(playbook.PLAYBOOK_POLICY) == {LOW, MEDIUM, HIGH, CRITICAL}
