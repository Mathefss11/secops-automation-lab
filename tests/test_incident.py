import hashlib
import json
import sys
from pathlib import Path

import pytest

import main
from src.detection_engine import CREDENTIAL_ATTACK, PAYLOAD_EXECUTION, SUSPICIOUS_POWERSHELL, run_detections
from src.enrichment import enrich_detections
from src.incident import SIMULATION_DISCLAIMER, create_incidents, incident_id_for
from src.normalizer import normalize_events
from src.playbook import run_playbooks
from src.threat_intel import MOCK_SOURCE, CachedThreatIntel, MockThreatIntelProvider

DATA_FILE = Path(__file__).resolve().parent.parent / "data" / "security_events.json"


def build_incidents():
    events, _ = normalize_events(json.loads(DATA_FILE.read_text(encoding="utf-8")))
    enriched = enrich_detections(run_detections(events), CachedThreatIntel(MockThreatIntelProvider()))
    return run_playbooks(create_incidents(enriched))


@pytest.fixture(scope="module")
def incidents():
    return {incident.detection.name: incident for incident in build_incidents()}


def test_one_incident_per_detection(incidents):
    assert set(incidents) == {CREDENTIAL_ATTACK, SUSPICIOUS_POWERSHELL, PAYLOAD_EXECUTION}


def test_incident_ids_are_deterministic(incidents):
    for incident in incidents.values():
        expected = "INC-" + hashlib.sha256(incident.detection.detection_id.encode()).hexdigest()[:10]
        assert incident.incident_id == expected == incident_id_for(incident.detection)
    assert [i.incident_id for i in build_incidents()] == [i.incident_id for i in build_incidents()]


def test_reports_are_identical_across_runs():
    first = [incident.to_report() for incident in build_incidents()]
    second = [incident.to_report() for incident in build_incidents()]
    assert first == second


def test_incidents_ordered_by_risk():
    scores = [incident.risk_score for incident in build_incidents()]
    assert scores == sorted(scores, reverse=True)


def test_incident_uses_composition(incidents):
    incident = incidents[CREDENTIAL_ATTACK]
    assert incident.detection is incident.enriched_detection.detection
    assert incident.severity == incident.detection.severity == "HIGH"
    assert incident.created_at == incident.detection.last_seen
    assert incident.title == "Possible Credential Compromise"


def test_report_contains_all_expected_context(incidents):
    report = incidents[CREDENTIAL_ATTACK].to_report()

    assert report["incident_id"].startswith("INC-")
    assert report["risk"]["score"] == 76 and report["risk"]["level"] == "HIGH"
    detection = report["detection"]
    assert detection["severity"] == "HIGH"
    assert detection["confidence"] == 0.90
    assert detection["host"] == "web-prod-01"
    assert detection["user"] == "deploy"
    assert detection["source_ip"] == "203.0.113.45"
    assert len(detection["evidence"]) == 7
    assert "not classified as password spraying" in detection["reasoning"]
    assert report["related_detections"] == [incidents[PAYLOAD_EXECUTION].detection.detection_id]


def test_mitre_data_survives(incidents):
    report = incidents[SUSPICIOUS_POWERSHELL].to_report()
    ids = [t["technique_id"] for t in report["mitre_attack"]]
    assert ids == ["T1059.001", "T1027.010", "T1564.003", "T1105"]
    assert all(t["reason"] and t["url"] for t in report["mitre_attack"])


def test_threat_intel_survives_and_stays_labelled(incidents):
    report = incidents[SUSPICIOUS_POWERSHELL].to_report()
    assert [(r["indicator"], r["reputation"]) for r in report["threat_intel"]] == [
        ("192.0.2.80", "SUSPICIOUS"),
        ("192.0.2.81", "UNKNOWN"),
    ]
    assert all(r["simulated"] is True and r["source"] == MOCK_SOURCE for r in report["threat_intel"])


def test_risk_explanation_survives(incidents):
    risk = incidents[PAYLOAD_EXECUTION].to_report()["risk"]
    assert sum(c["points"] for c in risk["contributors"]) == risk["score"] == 98
    assert {c["category"] for c in risk["contributors"]} == {
        "detection_evidence",
        "observed_outcome",
        "related_activity",
        "threat_intel",
    }
    assert risk["score_without_threat_intel"] == 88


def test_playbook_actions_survive(incidents):
    report = incidents[PAYLOAD_EXECUTION].to_report()
    actions = [(a["action_type"], a["target"]) for a in report["playbook_actions"]]
    assert actions == [
        ("RECORD_INCIDENT", report["incident_id"]),
        ("ESCALATE_TO_ANALYST", report["incident_id"]),
        ("SIMULATE_ENDPOINT_ISOLATION", "web-prod-01"),
        ("SIMULATE_IP_BLOCK", "198.51.100.77"),
    ]
    assert all(a["simulated"] is True for a in report["playbook_actions"])
    assert report["simulated_response"] is True
    assert report["disclaimer"] == SIMULATION_DISCLAIMER


def test_recommendations_are_the_approval_actions(incidents):
    report = incidents[CREDENTIAL_ATTACK].to_report()
    assert [(a["action_type"], a["target"]) for a in report["recommendations"]] == [
        ("RECOMMEND_ACCOUNT_DISABLE", "deploy"),
        ("RECOMMEND_IP_BLOCK", "203.0.113.45"),
    ]
    assert all(a["requires_approval"] for a in report["recommendations"])


def test_report_is_valid_json(incidents):
    for incident in incidents.values():
        assert json.loads(json.dumps(incident.to_report())) == incident.to_report()


# --- Export and CLI ---------------------------------------------------------------


def run_cli(monkeypatch, capsys, *args):
    monkeypatch.setattr(sys, "argv", ["main.py", *args])
    exit_code = main.main()
    return exit_code, capsys.readouterr().out


def test_export_writes_one_report_per_incident(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(main, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(main, "DEFAULT_EXPORT", tmp_path / "output" / "normalized_events.json")
    monkeypatch.setattr(main, "DETECTIONS_EXPORT", tmp_path / "output" / "detections.json")
    monkeypatch.setattr(main, "INCIDENTS_DIR", tmp_path / "output" / "incidents")

    exit_code, _ = run_cli(monkeypatch, capsys, "--incidents-only", "--export")

    files = sorted((tmp_path / "output" / "incidents").glob("INC-*.json"))
    assert exit_code == 0
    assert len(files) == 3  # distinct names: no report overwrites another
    for path in files:
        report = json.loads(path.read_text(encoding="utf-8"))
        assert path.stem == report["incident_id"]
        assert report["simulated_response"] is True
    # previous exports are still produced
    assert len(json.loads((tmp_path / "output" / "detections.json").read_text(encoding="utf-8"))) == 3
    assert (tmp_path / "output" / "normalized_events.json").exists()


def test_cli_prints_incidents_with_simulated_actions(monkeypatch, capsys):
    exit_code, out = run_cli(monkeypatch, capsys, "--incidents-only")
    assert exit_code == 0
    assert "[CRITICAL] Possible Payload Execution on Linux Host" in out
    assert "[SIMULATED ACTION] SIMULATE_ENDPOINT_ISOLATION: Isolate host web-prod-01" in out
    assert "[SIMULATED ACTION] RECOMMEND_ACCOUNT_DISABLE: Disable account deploy  (needs analyst approval)" in out
    assert "[+] 3 incident(s)" in out
    action_lines = [line for line in out.splitlines() if "_INCIDENT:" in line or "RECOMMEND_" in line or "SIMULATE_" in line]
    assert action_lines and all("[SIMULATED ACTION]" in line for line in action_lines)


def test_inspect_incident(monkeypatch, capsys, incidents):
    incident_id = incidents[CREDENTIAL_ATTACK].incident_id
    exit_code, out = run_cli(monkeypatch, capsys, "--inspect", incident_id)
    assert exit_code == 0
    assert json.loads(out)["incident_id"] == incident_id
