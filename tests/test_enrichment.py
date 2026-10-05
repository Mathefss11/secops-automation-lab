import copy
import json
import sys
from pathlib import Path

import pytest

import main
from src.detection_engine import CREDENTIAL_ATTACK, PAYLOAD_EXECUTION, SUSPICIOUS_POWERSHELL, run_detections
from src.enrichment import enrich_detection, enrich_detections, indicators_for
from src.normalizer import normalize_events
from src.threat_intel import (
    ABUSEIPDB_API_KEY_ENV,
    MOCK_SOURCE,
    CachedThreatIntel,
    MockThreatIntelProvider,
)

DATA_FILE = Path(__file__).resolve().parent.parent / "data" / "security_events.json"


@pytest.fixture
def detections():
    events, _ = normalize_events(json.loads(DATA_FILE.read_text(encoding="utf-8")))
    return run_detections(events)


def by_name(enriched_detections):
    return {enriched.detection.name: enriched for enriched in enriched_detections}


def mock_intel():
    return CachedThreatIntel(MockThreatIntelProvider())


def test_indicators_per_detection(detections):
    indicators = {d.name: indicators_for(d) for d in detections}
    assert indicators[CREDENTIAL_ATTACK] == ["203.0.113.45"]
    assert indicators[SUSPICIOUS_POWERSHELL] == ["192.0.2.80", "192.0.2.81"]
    assert indicators[PAYLOAD_EXECUTION] == ["198.51.100.77"]


def test_all_three_detections_are_enriched(detections):
    enriched = by_name(enrich_detections(detections, mock_intel()))

    assert len(enriched) == 3
    assert all(e.mitre_techniques for e in enriched.values())
    assert all(e.threat_intel for e in enriched.values())
    assert enriched[CREDENTIAL_ATTACK].threat_intel[0].indicator == "203.0.113.45"


def test_enrichment_does_not_change_the_detection(detections):
    original = copy.deepcopy(detections[0])
    enriched = enrich_detection(detections[0], mock_intel())
    assert enriched.detection == original
    assert enriched.detection.confidence == original.confidence  # TI is context, not scoring


def test_duplicate_indicators_across_detections_use_cache(detections):
    intel = mock_intel()
    enrich_detections(detections + detections, intel)  # every indicator appears twice
    assert intel.provider_calls == 4
    assert intel.cache_hits == 4


def test_disabled_threat_intel_still_maps_mitre(detections):
    enriched = by_name(enrich_detections(detections, None, f"{ABUSEIPDB_API_KEY_ENV} is not set"))
    for item in enriched.values():
        assert item.threat_intel == []
        assert item.mitre_techniques
        assert item.threat_intel_status.startswith("not queried")


def test_export_keeps_detection_fields_and_labels_mock_data(detections):
    exported = enrich_detections(detections, mock_intel())[0].to_dict()

    assert {"detection_id", "name", "severity", "confidence", "evidence"} <= exported.keys()
    assert exported["mitre_attack"][0]["technique_id"].startswith("T")
    assert exported["mitre_attack"][0]["url"].startswith("https://attack.mitre.org/")
    for result in exported["threat_intel"]:
        assert result["simulated"] is True
        assert result["source"] == MOCK_SOURCE
    assert "SIMULATED" in exported["threat_intel_status"]
    json.dumps(exported)  # serializable


# --- CLI ---------------------------------------------------------------------


def run_cli(monkeypatch, capsys, *args):
    monkeypatch.setattr(sys, "argv", ["main.py", *args])
    exit_code = main.main()
    return exit_code, capsys.readouterr().out


def test_default_cli_is_offline_and_labels_mock(monkeypatch, capsys):
    # Network is blocked by conftest; the default run must succeed anyway.
    exit_code, out = run_cli(monkeypatch, capsys, "--no-timeline")

    assert exit_code == 0
    assert "offline, no network requests" in out
    assert out.count("[SIMULATED]") == 4
    assert "T1110 - Brute Force" in out
    assert "[+] 3 detection(s)" in out


def test_cli_without_api_key_explains_and_does_not_crash(monkeypatch, capsys):
    monkeypatch.delenv(ABUSEIPDB_API_KEY_ENV, raising=False)
    exit_code, out = run_cli(monkeypatch, capsys, "--no-timeline", "--threat-intel", "abuseipdb")

    assert exit_code == 0
    assert f"{ABUSEIPDB_API_KEY_ENV} is not set, so AbuseIPDB was NOT queried" in out
    assert "[+] 3 detection(s)" in out
    assert "[SIMULATED]" not in out  # no silent fallback to mock data


def test_cli_with_key_never_sends_simulated_documentation_ips(monkeypatch, capsys):
    monkeypatch.setenv(ABUSEIPDB_API_KEY_ENV, "test-key-not-real")
    exit_code, out = run_cli(monkeypatch, capsys, "--no-timeline", "--threat-intel", "abuseipdb")

    assert exit_code == 0
    assert out.count("not a publicly routable") == 4
    assert "test-key-not-real" not in out


def test_lookup_ip_without_key_returns_error_code(monkeypatch, capsys):
    monkeypatch.delenv(ABUSEIPDB_API_KEY_ENV, raising=False)
    exit_code, out = run_cli(monkeypatch, capsys, "--threat-intel", "abuseipdb", "--lookup-ip", "8.8.8.8")
    assert exit_code == 2
    assert "NOT queried" in out


def test_inspect_detection_includes_enrichment(monkeypatch, capsys, detections):
    detection_id = detections[0].detection_id
    exit_code, out = run_cli(monkeypatch, capsys, "--inspect", detection_id)
    record = json.loads(out)
    assert exit_code == 0
    assert record["detection_id"] == detection_id
    assert record["mitre_attack"] and record["threat_intel"]


def test_inspect_event_still_works(monkeypatch, capsys):
    exit_code, out = run_cli(monkeypatch, capsys, "--inspect", "0910fc527510")
    assert exit_code == 0
    assert json.loads(out)["raw_event"]["user"] == "alice"
