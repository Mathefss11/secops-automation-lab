import json
from pathlib import Path

import pytest

from src.detection_engine import (
    CREDENTIAL_ATTACK,
    PAYLOAD_EXECUTION,
    SUSPICIOUS_POWERSHELL,
    Detection,
    Evidence,
    run_detections,
)
from src.enrichment import EnrichedDetection, enrich_detections
from src.incident import create_incidents
from src.normalizer import normalize_events
from src.risk_engine import (
    CRITICAL,
    EVIDENCE_MAX_POINTS,
    HIGH,
    LOW,
    MEDIUM,
    OUTCOME_MAX_POINTS,
    assess_risk,
    find_related_detections,
    risk_level,
)
from src.threat_intel import (
    BENIGN,
    MALICIOUS,
    MOCK_SOURCE,
    SUSPICIOUS,
    UNKNOWN,
    CachedThreatIntel,
    MockThreatIntelProvider,
    ThreatIntelResult,
    unavailable_result,
)

DATA_FILE = Path(__file__).resolve().parent.parent / "data" / "security_events.json"


def make_detection(name=SUSPICIOUS_POWERSHELL, confidence=0.55, host="WS-01", user="alex", source_ip=None,
                   details=None, first_seen="2026-09-14T09:00:00.000Z", detection_id="DET-test000001"):
    return Detection(
        detection_id=detection_id,
        name=name,
        description="test",
        severity=HIGH,
        confidence=confidence,
        first_seen=first_seen,
        last_seen=first_seen,
        host=host,
        user=user,
        source_ip=source_ip,
        reasoning="test",
        signals=[],
        evidence=[Evidence("evt-1", first_seen, "test")],
        details=details or {},
    )


def intel(reputation, ip="192.0.2.10"):
    return ThreatIntelResult(ip, "ip", reputation, 0.9, [], MOCK_SOURCE, True)


def enriched(detection, *results):
    return EnrichedDetection(detection, [], list(results), "test")


def contributor_points(assessment, category):
    return sum(c.points for c in assessment.contributors if c.category == category)


@pytest.fixture(scope="module")
def dataset_incidents():
    events, _ = normalize_events(json.loads(DATA_FILE.read_text(encoding="utf-8")))
    enriched_detections = enrich_detections(run_detections(events), CachedThreatIntel(MockThreatIntelProvider()))
    return {incident.detection.name: incident for incident in create_incidents(enriched_detections)}


# --- Bundled dataset (manually verified values) ----------------------------


def test_dataset_scores_and_levels(dataset_incidents):
    scores = {name: (i.risk_score, i.risk_level) for name, i in dataset_incidents.items()}
    assert scores == {
        PAYLOAD_EXECUTION: (98, CRITICAL),  # 38 + 25 + 10 + 15 + 10
        SUSPICIOUS_POWERSHELL: (78, HIGH),  # 38 + 25 + 10 + 0 + 5
        CREDENTIAL_ATTACK: (76, HIGH),  # 36 + 15 + 0 + 15 + 10
    }


def test_not_every_simulated_attack_is_critical(dataset_incidents):
    levels = [incident.risk_level for incident in dataset_incidents.values()]
    assert levels.count(CRITICAL) == 1


def test_contributors_add_up_to_the_score(dataset_incidents):
    for incident in dataset_incidents.values():
        assert sum(c.points for c in incident.risk_contributors) == incident.risk_score
        assert all(c.reason for c in incident.risk_contributors)


def test_credential_and_payload_incidents_reference_each_other(dataset_incidents):
    credential = dataset_incidents[CREDENTIAL_ATTACK]
    payload = dataset_incidents[PAYLOAD_EXECUTION]
    assert credential.risk.related_detection_ids == [payload.detection.detection_id]
    assert payload.risk.related_detection_ids == [credential.detection.detection_id]
    assert dataset_incidents[SUSPICIOUS_POWERSHELL].risk.related_detection_ids == []


def test_mock_intel_never_decides_the_level_in_the_dataset(dataset_incidents):
    for incident in dataset_incidents.values():
        assert risk_level(incident.risk.score_without_threat_intel) == incident.risk_level


# --- Bounds, determinism, thresholds ------------------------------------------


@pytest.mark.parametrize(
    "score, level",
    [(0, LOW), (39, LOW), (40, MEDIUM), (59, MEDIUM), (60, HIGH), (79, HIGH), (80, CRITICAL), (100, CRITICAL)],
)
def test_risk_level_thresholds(score, level):
    assert risk_level(score) == level


def test_score_stays_within_0_and_100():
    maximum = make_detection(
        PAYLOAD_EXECUTION, confidence=1.0, details={"downloaded_path": "/tmp/x", "external_ips": ["192.0.2.10"]}
    )
    related = make_detection(CREDENTIAL_ATTACK, detection_id="DET-other00001")
    high = assess_risk(enriched(maximum, intel(MALICIOUS)), [related])
    low = assess_risk(enriched(make_detection(name="Unknown Detection", confidence=0.0)))
    assert high.score == 100
    assert low.score == 0
    assert 0 <= low.score <= high.score <= 100


def test_assessment_is_deterministic():
    detection = make_detection(details={"executed_files": ["C:\\x.exe"], "external_ips": ["192.0.2.10"]})
    first = assess_risk(enriched(detection, intel(SUSPICIOUS)))
    second = assess_risk(enriched(detection, intel(SUSPICIOUS)))
    assert first == second


# --- Threat intelligence is context, not authority -------------------------


def test_malicious_intel_adds_at_most_ten_points():
    detection = make_detection()
    without = assess_risk(enriched(detection))
    with_malicious = assess_risk(enriched(detection, intel(MALICIOUS)))
    assert 0 < with_malicious.score - without.score <= 10


def test_malicious_intel_alone_cannot_create_a_high_or_critical_incident():
    weak = make_detection(confidence=0.35)  # script execution only, no follow-on activity
    assessment = assess_risk(enriched(weak, intel(MALICIOUS)))
    assert assessment.level in (LOW, MEDIUM)


def test_threat_intel_cannot_be_the_only_reason_for_critical():
    # 38 evidence + 25 execution + 10 outbound = 73 (HIGH); + 10 malicious intel = 83
    detection = make_detection(
        PAYLOAD_EXECUTION, confidence=0.95, details={"downloaded_path": "/tmp/x", "external_ips": ["192.0.2.10"]}
    )
    assessment = assess_risk(enriched(detection, intel(MALICIOUS)))
    assert assessment.score == 83
    assert assessment.score_without_threat_intel == 73
    assert assessment.level == HIGH
    assert "threat intelligence alone cannot" in assessment.level_note


def test_unknown_and_benign_reputation_do_not_reduce_risk():
    detection = make_detection()
    baseline = assess_risk(enriched(detection)).score
    assert assess_risk(enriched(detection, intel(UNKNOWN))).score == baseline
    assert assess_risk(enriched(detection, intel(BENIGN))).score == baseline


def test_unavailable_intel_is_handled():
    detection = make_detection()
    failed = unavailable_result("8.8.8.8", "AbuseIPDB", False, "could not connect to AbuseIPDB")
    assessment = assess_risk(enriched(detection, failed))
    assert contributor_points(assessment, "threat_intel") == 0
    assert any("lookups failed" in c.reason for c in assessment.contributors)


def test_suspicious_counts_less_than_malicious():
    detection = make_detection()
    suspicious = assess_risk(enriched(detection, intel(SUSPICIOUS))).score
    malicious = assess_risk(enriched(detection, intel(MALICIOUS))).score
    assert suspicious < malicious


# --- Evidence and outcome -------------------------------------------------------


@pytest.mark.parametrize("low, high", [(0.40, 0.60), (0.60, 0.90), (0.90, 0.95)])
def test_higher_confidence_never_lowers_risk(low, high):
    details = {"executed_files": ["C:\\x.exe"]}
    assert (
        assess_risk(enriched(make_detection(confidence=low, details=details))).score
        <= assess_risk(enriched(make_detection(confidence=high, details=details))).score
    )


def test_low_confidence_without_outcome_is_low_risk():
    assessment = assess_risk(enriched(make_detection(confidence=0.35)))
    assert assessment.score == 29  # 14 evidence + 15 script execution
    assert assessment.level == LOW


def test_evidence_points_are_confidence_times_forty():
    assessment = assess_risk(enriched(make_detection(confidence=0.9)))
    assert contributor_points(assessment, "detection_evidence") == 36
    assert contributor_points(assessment, "detection_evidence") <= EVIDENCE_MAX_POINTS


# --- No double counting ---------------------------------------------------------


def test_launch_context_signals_only_count_through_confidence():
    """The same confidence gives the same score, however many signal strings back it."""
    few = make_detection(confidence=0.55)
    many = make_detection(confidence=0.55)
    many.signals.extend(["office parent (+0.25)", "encoded (+0.20)", "hidden (+0.10)"])
    assert assess_risk(enriched(few)).score == assess_risk(enriched(many)).score


def test_execution_stages_do_not_stack():
    detection = make_detection(details={"executed_files": ["C:\\x.exe"]})
    assessment = assess_risk(enriched(detection))
    # payload execution (25) replaces script execution (15); it is not added to it
    assert contributor_points(assessment, "observed_outcome") == 25


def test_outcome_category_is_capped():
    detection = make_detection(details={"executed_files": ["C:\\x.exe"], "external_ips": ["192.0.2.1", "192.0.2.2"]})
    assert contributor_points(assess_risk(enriched(detection)), "observed_outcome") <= OUTCOME_MAX_POINTS


def test_each_indicator_counts_once_even_if_several_are_malicious():
    detection = make_detection()
    one = assess_risk(enriched(detection, intel(MALICIOUS, "192.0.2.1"))).score
    three = assess_risk(
        enriched(detection, intel(MALICIOUS, "192.0.2.1"), intel(MALICIOUS, "192.0.2.2"), intel(MALICIOUS, "192.0.2.3"))
    ).score
    assert one == three


# --- Related detections ---------------------------------------------------------


def test_related_requires_same_host_and_user_within_window():
    base = make_detection(host="srv-01", user="deploy", detection_id="DET-a")
    same = make_detection(host="srv-01", user="deploy", first_seen="2026-09-14T09:30:00.000Z", detection_id="DET-b")
    other_user = make_detection(host="srv-01", user="alice", detection_id="DET-c")
    other_host = make_detection(host="srv-02", user="deploy", detection_id="DET-d")
    too_late = make_detection(host="srv-01", user="deploy", first_seen="2026-09-14T11:00:00.000Z", detection_id="DET-e")

    related = find_related_detections(base, [base, same, other_user, other_host, too_late])
    assert [d.detection_id for d in related] == ["DET-b"]


def test_detection_without_user_has_no_related_activity():
    no_user = make_detection(user=None, detection_id="DET-a")
    other = make_detection(user=None, detection_id="DET-b")
    assert find_related_detections(no_user, [no_user, other]) == []
