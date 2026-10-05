"""Behavioral detections over normalized events.

Each detector looks for a *sequence* of related events rather than a single
"bad" event. A failed login, a PowerShell process or a curl command is not
suspicious on its own; the detectors only fire when several events line up on
the same host, user, process or file within a time window.

Confidence is a deterministic sum of documented signal weights (no ML). It
expresses how strongly the correlated evidence supports the detection, not the
overall incident risk, which a later phase will calculate.
"""

from __future__ import annotations

import hashlib
import ipaddress
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from typing import Any

from src.command_analysis import (
    DOWNLOAD_TOOLS,
    OFFICE_IMAGES,
    POWERSHELL_IMAGES,
    basename,
    file_name,
    decode_encoded_command,
    get_chmod_execute_targets,
    get_download_output_path,
    get_encoded_command,
    has_hidden_window,
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
)

LOW = "LOW"
MEDIUM = "MEDIUM"
HIGH = "HIGH"
CRITICAL = "CRITICAL"  # reserved; no Phase 2 detection is confident enough to use it

# Correlated evidence never proves intent, so confidence is capped below 1.0.
MAX_CONFIDENCE = 0.95


@dataclass(frozen=True)
class DetectionConfig:
    """Thresholds and correlation windows. Change these to tune the detectors."""

    # Credential attack: failures from one source IP before a success.
    auth_window: timedelta = timedelta(minutes=5)
    auth_min_failures: int = 5
    auth_min_distinct_accounts: int = 3

    # Suspicious PowerShell: activity by the same process after it started.
    powershell_window: timedelta = timedelta(minutes=5)
    powershell_min_confidence: float = 0.35

    # Payload download and execution: download -> chmod -> execution -> network.
    payload_window: timedelta = timedelta(minutes=15)


DEFAULT_CONFIG = DetectionConfig()


@dataclass
class Evidence:
    """Reference to a normalized event plus why it matters."""

    event_id: str
    timestamp: str
    description: str


@dataclass
class Detection:
    detection_id: str
    name: str
    description: str
    severity: str
    confidence: float
    first_seen: str
    last_seen: str
    host: str | None
    user: str | None
    source_ip: str | None
    reasoning: str
    signals: list[str]
    evidence: list[Evidence]
    details: dict[str, Any] = field(default_factory=dict)
    false_positives: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# --- Shared helpers ---------------------------------------------------------


def _time(event: NormalizedEvent) -> datetime:
    """Parse the normalized UTC timestamp into a timezone-aware datetime."""
    return datetime.fromisoformat(event.timestamp.replace("Z", "+00:00"))


def _chronological(events: list[NormalizedEvent]) -> list[NormalizedEvent]:
    """Never trust input order: correlate on parsed timestamps."""
    return sorted(events, key=_time)


def _seconds_between(first: NormalizedEvent, second: NormalizedEvent) -> int:
    return int((_time(second) - _time(first)).total_seconds())


# Private, loopback and link-local ranges. Python's ``is_private`` is not used
# because it also treats the RFC 5737 documentation ranges as private, and the
# simulated attacker uses those ranges to stand in for public internet IPs.
INTERNAL_NETWORKS = [
    ipaddress.ip_network(network)
    for network in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    )
]


def is_external_ip(ip: str | None) -> bool:
    """True if ``ip`` is a valid address outside ``INTERNAL_NETWORKS``."""
    if not ip:
        return False
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not any(address in network for network in INTERNAL_NETWORKS)


def _same_path(a: str | None, b: str | None, case_sensitive: bool = True) -> bool:
    if not a or not b:
        return False
    return a == b if case_sensitive else a.lower() == b.lower()


def _same_process(event: NormalizedEvent, process_event: NormalizedEvent) -> bool:
    """Same host, same image and same PID as the PROCESS_CREATE event.

    PIDs are reused by operating systems, so the PID is only trusted together
    with host, image path and the correlation time window used by the caller.
    """
    return (
        event.host is not None
        and event.host == process_event.host
        and event.process_id is not None
        and event.process_id == process_event.process_id
        and _same_path(event.process, process_event.process, case_sensitive=False)
    )


def _is_child_of(event: NormalizedEvent, parent: NormalizedEvent) -> bool:
    """PROCESS_CREATE ``event`` was started by the ``parent`` process instance."""
    return (
        event.event_type == PROCESS_CREATE
        and event.host is not None
        and event.host == parent.host
        and parent.process_id is not None
        and event.parent_process_id == parent.process_id
        and _same_path(event.parent_process, parent.process, case_sensitive=False)
    )


def _same_actor(a: NormalizedEvent, b: NormalizedEvent) -> bool:
    """Same host, and same user when both events record one."""
    if a.host is None or a.host != b.host:
        return False
    return a.user is None or b.user is None or a.user == b.user


def _confidence(weights: dict[str, float], signals: list[str], base: float = 0.0) -> float:
    return round(min(MAX_CONFIDENCE, base + sum(weights[name] for name in signals)), 2)


def _describe_signals(weights: dict[str, float], signals: list[str], labels: dict[str, str]) -> list[str]:
    return [f"{labels[name]} (+{weights[name]:.2f})" for name in signals]


def _make_detection(name: str, evidence: list[Evidence], **fields: Any) -> Detection:
    evidence = sorted(evidence, key=lambda item: item.timestamp)
    # Deterministic ID: the same evidence always produces the same detection ID.
    digest = hashlib.sha256((name + "|" + "|".join(e.event_id for e in evidence)).encode()).hexdigest()
    return Detection(
        detection_id=f"DET-{digest[:10]}",
        name=name,
        first_seen=evidence[0].timestamp,
        last_seen=evidence[-1].timestamp,
        evidence=evidence,
        **fields,
    )


def _evidence(event: NormalizedEvent, description: str) -> Evidence:
    return Evidence(event.event_id, event.timestamp, description)


# --- Detection 1: credential attack followed by successful authentication --

CREDENTIAL_ATTACK = "Credential Attack Followed by Successful Authentication"

CREDENTIAL_BASE_CONFIDENCE = 0.70  # thresholds met and a success followed
CREDENTIAL_WEIGHTS = {
    "external_source": 0.10,
    "failed_account_later_succeeded": 0.10,
}
CREDENTIAL_LABELS = {
    "external_source": "source IP is outside internal address ranges",
    "failed_account_later_succeeded": "the account that logged in had failed earlier in the same burst",
}
CREDENTIAL_FALSE_POSITIVES = [
    "A user repeatedly mistyping a password (usually one account, not several).",
    "Automated jobs or services retrying stale credentials.",
    "Authorized vulnerability scanners or penetration tests.",
    "Shared NAT/VPN egress IPs that aggregate many users' logins.",
]


def _failures_before(
    success: NormalizedEvent, auth_events: list[NormalizedEvent], window: timedelta
) -> list[NormalizedEvent]:
    """Failures from the same source IP against the same host, inside the
    window that ends at the successful login."""
    window_start = _time(success) - window
    return [
        event
        for event in auth_events
        if event.result == FAILURE
        and event.source_ip == success.source_ip
        and event.host == success.host
        and window_start <= _time(event) <= _time(success)
    ]


def _unique_in_order(values: list[str | None]) -> list[str]:
    seen: list[str] = []
    for value in values:
        if value is not None and value not in seen:
            seen.append(value)
    return seen


def detect_credential_attack(
    events: list[NormalizedEvent], config: DetectionConfig = DEFAULT_CONFIG
) -> list[Detection]:
    """Many failures against several accounts from one source IP, followed by
    a successful login from that same IP to the same host.

    This is NOT labelled password spraying: the telemetry does not show
    whether the same password was tried against each account.
    """
    auth_events = [
        event
        for event in _chronological(events)
        if event.event_type == AUTHENTICATION and event.source_ip is not None
    ]
    detections = []
    already_reported: set[str] = set()  # failures already used by an earlier detection

    for success in (event for event in auth_events if event.result == SUCCESS):
        failures = [
            event
            for event in _failures_before(success, auth_events, config.auth_window)
            if event.event_id not in already_reported
        ]
        accounts = _unique_in_order([event.user for event in failures])
        if len(failures) < config.auth_min_failures or len(accounts) < config.auth_min_distinct_accounts:
            continue

        already_reported.update(event.event_id for event in failures)
        detections.append(_credential_detection(success, failures, accounts))
    return detections


def _credential_detection(
    success: NormalizedEvent, failures: list[NormalizedEvent], accounts: list[str]
) -> Detection:
    signals = []
    if is_external_ip(success.source_ip):
        signals.append("external_source")
    if success.user in accounts:
        signals.append("failed_account_later_succeeded")

    elapsed = _seconds_between(failures[0], success)
    reasoning = (
        f"{len(failures)} failed authentication attempts against {len(accounts)} distinct accounts "
        f"({', '.join(accounts)}) from {success.source_ip} on {success.host} were followed by a "
        f"successful authentication as '{success.user}' from the same source IP, {elapsed} seconds "
        f"after the first failure. This is consistent with credential guessing that may have "
        f"succeeded. The telemetry does not show whether the same password was reused across "
        f"accounts, so it is not classified as password spraying."
    )
    evidence = [_evidence(event, f"authentication failure for '{event.user}'") for event in failures]
    evidence.append(_evidence(success, f"authentication success for '{success.user}'"))

    return _make_detection(
        CREDENTIAL_ATTACK,
        evidence,
        description="Multiple failed logins against several accounts from one source, then a successful login from that source.",
        severity=HIGH,
        confidence=_confidence(CREDENTIAL_WEIGHTS, signals, base=CREDENTIAL_BASE_CONFIDENCE),
        host=success.host,
        user=success.user,
        source_ip=success.source_ip,
        reasoning=reasoning,
        signals=[f"base: thresholds met and success followed (+{CREDENTIAL_BASE_CONFIDENCE:.2f})"]
        + _describe_signals(CREDENTIAL_WEIGHTS, signals, CREDENTIAL_LABELS),
        details={
            "failed_attempts": len(failures),
            "targeted_accounts": accounts,
            "authenticated_account": success.user,
            "first_failure_event": failures[0].event_id,
            "success_event": success.event_id,
            "elapsed_seconds": elapsed,
        },
        false_positives=CREDENTIAL_FALSE_POSITIVES,
    )


# --- Detection 2: suspicious PowerShell execution ---------------------------

SUSPICIOUS_POWERSHELL = "Suspicious PowerShell Execution"

# Process-level signals: properties of the PowerShell process itself.
POWERSHELL_PROCESS_WEIGHTS = {
    "office_parent": 0.25,
    "encoded_command": 0.20,
    "hidden_window": 0.10,
}
# Behavioral signals: what the same process did after it started.
POWERSHELL_ACTIVITY_WEIGHTS = {
    "dns_query": 0.10,
    "external_connection": 0.10,
    "file_created": 0.05,
    "created_file_executed": 0.10,
    "executed_file_external_connection": 0.05,
}
POWERSHELL_WEIGHTS = POWERSHELL_PROCESS_WEIGHTS | POWERSHELL_ACTIVITY_WEIGHTS
POWERSHELL_LABELS = {
    "office_parent": "parent process is an Office application",
    "encoded_command": "command line uses -EncodedCommand",
    "hidden_window": "command line requests a hidden window",
    "dns_query": "the PowerShell process performed a DNS query",
    "external_connection": "the PowerShell process connected to an external IP",
    "file_created": "the PowerShell process created a file",
    "created_file_executed": "a file created by PowerShell was then executed as a child process",
    "executed_file_external_connection": "the executed file connected to an external IP",
}
POWERSHELL_FALSE_POSITIVES = [
    "Legitimate administrative automation and scheduled scripts.",
    "Software deployment and enterprise management tools (some use -EncodedCommand and hidden windows).",
    "Office add-ins or macros approved by the organization that call PowerShell.",
]


def _powershell_process_signals(process: NormalizedEvent) -> list[str]:
    signals = []
    if basename(process.parent_process) in OFFICE_IMAGES:
        signals.append("office_parent")
    if get_encoded_command(process.command_line):
        signals.append("encoded_command")
    if has_hidden_window(process.command_line):
        signals.append("hidden_window")
    return signals


def _in_window(event: NormalizedEvent, start: NormalizedEvent, window: timedelta) -> bool:
    return _time(start) <= _time(event) <= _time(start) + window


def _powershell_activity(
    process: NormalizedEvent, ordered: list[NormalizedEvent], window: timedelta
) -> tuple[list[str], list[Evidence], dict[str, Any]]:
    """Find what this specific PowerShell process did after it started."""
    signals: list[str] = []
    evidence: list[Evidence] = []
    later = [event for event in ordered if event is not process and _in_window(event, process, window)]

    queries = [e for e in later if e.event_type == DNS_QUERY and _same_process(e, process)]
    connections = [
        e
        for e in later
        if e.event_type == NETWORK_CONNECTION and _same_process(e, process) and is_external_ip(e.destination_ip)
    ]
    created_files = [e for e in later if e.event_type == FILE_CREATE and _same_process(e, process)]
    created_paths = {e.file_path.lower() for e in created_files if e.file_path}
    executed = [e for e in later if _is_child_of(e, process) and (e.process or "").lower() in created_paths]
    executed_connections = [
        e
        for e in later
        if e.event_type == NETWORK_CONNECTION
        and any(_same_process(e, child) for child in executed)
        and is_external_ip(e.destination_ip)
    ]

    if queries:
        signals.append("dns_query")
        evidence += [_evidence(e, f"DNS query for {e.dns_query} by PowerShell") for e in queries]
    if connections:
        signals.append("external_connection")
        evidence += [
            _evidence(e, f"PowerShell connection to {e.destination_ip}:{e.destination_port}") for e in connections
        ]
    if created_files:
        signals.append("file_created")
        evidence += [_evidence(e, f"file created by PowerShell: {e.file_path}") for e in created_files]
    if executed:
        signals.append("created_file_executed")
        evidence += [_evidence(e, f"created file executed: {e.process}") for e in executed]
    if executed_connections:
        signals.append("executed_file_external_connection")
        evidence += [
            _evidence(e, f"executed file connected to {e.destination_ip}:{e.destination_port}")
            for e in executed_connections
        ]

    details = {
        "dns_queries": [e.dns_query for e in queries],
        "external_destinations": [f"{e.destination_ip}:{e.destination_port}" for e in connections + executed_connections],
        # All external IPs, and the subset contacted by the PowerShell process itself.
        "external_ips": _unique_in_order([e.destination_ip for e in connections + executed_connections]),
        "powershell_external_ips": _unique_in_order([e.destination_ip for e in connections]),
        "created_files": [e.file_path for e in created_files],
        "executed_files": [e.process for e in executed],
    }
    return signals, evidence, details


def detect_suspicious_powershell(
    events: list[NormalizedEvent], config: DetectionConfig = DEFAULT_CONFIG
) -> list[Detection]:
    """PowerShell whose launch context and follow-on behavior are suspicious.

    A PowerShell process with no suspicious launch context is ignored even if
    it makes network connections: that alone is normal admin activity. When
    there is suspicious context, follow-on activity of the same process adds
    confidence. The detection fires once the total reaches
    ``config.powershell_min_confidence``.
    """
    ordered = _chronological(events)
    detections = []
    for process in ordered:
        if process.event_type != PROCESS_CREATE or basename(process.process) not in POWERSHELL_IMAGES:
            continue
        process_signals = _powershell_process_signals(process)
        if not process_signals:
            continue

        activity_signals, activity_evidence, details = _powershell_activity(process, ordered, config.powershell_window)
        signals = process_signals + activity_signals
        confidence = _confidence(POWERSHELL_WEIGHTS, signals)
        if confidence < config.powershell_min_confidence:
            continue
        detections.append(_powershell_detection(process, signals, confidence, activity_evidence, details))
    return detections


def _powershell_reasoning(process: NormalizedEvent, signals: list[str]) -> str:
    parent = file_name(process.parent_process) or "an unknown parent"
    flags = []
    if "hidden_window" in signals:
        flags.append("hidden-window")
    if "encoded_command" in signals:
        flags.append("encoded-command")

    text = f"{parent} spawned PowerShell on {process.host}"
    if flags:
        text += f" with {' and '.join(flags)} arguments"
    text += "."

    follow_up = [POWERSHELL_LABELS[name] for name in signals if name in POWERSHELL_ACTIVITY_WEIGHTS]
    if follow_up:
        text += " Afterwards, " + "; ".join(follow_up) + "."
    text += (
        " Together these behaviors are suspicious and require investigation. The telemetry does not"
        " show what data, if any, was transferred, and the destinations are not confirmed as malicious."
    )
    return text


def _powershell_detection(
    process: NormalizedEvent,
    signals: list[str],
    confidence: float,
    activity_evidence: list[Evidence],
    details: dict[str, Any],
) -> Detection:
    encoded = get_encoded_command(process.command_line)
    evidence = [_evidence(process, f"PowerShell started by {file_name(process.parent_process)}")] + activity_evidence
    return _make_detection(
        SUSPICIOUS_POWERSHELL,
        evidence,
        description="PowerShell launched with suspicious context and correlated follow-on activity by the same process.",
        severity=HIGH if confidence >= 0.70 else MEDIUM,
        confidence=confidence,
        host=process.host,
        user=process.user,
        source_ip=None,
        reasoning=_powershell_reasoning(process, signals),
        signals=_describe_signals(POWERSHELL_WEIGHTS, signals, POWERSHELL_LABELS),
        details={
            "process": process.process,
            "parent_process": process.parent_process,
            "process_id": process.process_id,
            "command_line": process.command_line,
            # Decoded for analyst context only. It is never executed.
            "decoded_command": decode_encoded_command(encoded) if encoded else None,
            **details,
        },
        false_positives=POWERSHELL_FALSE_POSITIVES,
    )


# --- Detection 3: payload download and execution ----------------------------

PAYLOAD_EXECUTION = "Payload Download and Execution"

PAYLOAD_BASE_CONFIDENCE = 0.55  # download command + execution of the same file
PAYLOAD_WEIGHTS = {
    "file_create_observed": 0.05,
    "made_executable": 0.20,
    "temporary_or_hidden_path": 0.05,
    "external_connection_after_execution": 0.10,
}
PAYLOAD_LABELS = {
    "file_create_observed": "file creation at the download path was observed",
    "made_executable": "execute permission was added to the downloaded file",
    "temporary_or_hidden_path": "file is in a temporary directory or has a hidden name",
    "external_connection_after_execution": "the executed file connected to an external IP",
}
PAYLOAD_FALSE_POSITIVES = [
    "Software installation scripts (curl ... -o /tmp/install.sh && chmod +x && run).",
    "DevOps / CI automation that fetches and runs build tools.",
    "Administrators downloading legitimate temporary installers or agents.",
]
TEMPORARY_DIRECTORIES = ("/tmp/", "/var/tmp/", "/dev/shm/")


def _find_execution(
    download: NormalizedEvent, path: str, ordered: list[NormalizedEvent], window: timedelta
) -> NormalizedEvent | None:
    """First execution of ``path`` by the same actor after the download."""
    for event in ordered:
        if (
            event.event_type == PROCESS_CREATE
            and _same_path(event.process, path)
            and _same_actor(event, download)
            and _time(download) < _time(event) <= _time(download) + window
        ):
            return event
    return None


def _between(event: NormalizedEvent, start: NormalizedEvent, end: NormalizedEvent) -> bool:
    return _time(start) <= _time(event) <= _time(end)


def _permission_changes(
    path: str, download: NormalizedEvent, execution: NormalizedEvent, ordered: list[NormalizedEvent]
) -> list[NormalizedEvent]:
    """chmod commands (or chmod file-modification events) on ``path`` between
    the download and the execution."""
    changes = []
    for event in ordered:
        if event is download or not _same_actor(event, download) or not _between(event, download, execution):
            continue
        if event.event_type == PROCESS_CREATE and path in get_chmod_execute_targets(event.command_line):
            changes.append(event)
        elif (
            event.event_type == FILE_MODIFICATION
            and _same_path(event.file_path, path)
            and basename(event.process) == "chmod"
        ):
            changes.append(event)
    return changes


def detect_payload_execution(
    events: list[NormalizedEvent], config: DetectionConfig = DEFAULT_CONFIG
) -> list[Detection]:
    """curl/wget writes a file, and that same file is later executed on the
    same host by the same user. Execution evidence is required: a download on
    its own never produces this detection."""
    ordered = _chronological(events)
    detections = []
    for download in ordered:
        if download.event_type != PROCESS_CREATE or basename(download.process) not in DOWNLOAD_TOOLS:
            continue
        path = get_download_output_path(download.command_line)
        if path is None:
            continue
        execution = _find_execution(download, path, ordered, config.payload_window)
        if execution is None:
            continue
        detections.append(_payload_detection(download, path, execution, ordered, config.payload_window))
    return detections


def _payload_detection(
    download: NormalizedEvent,
    path: str,
    execution: NormalizedEvent,
    ordered: list[NormalizedEvent],
    window: timedelta,
) -> Detection:
    file_creates = [
        e
        for e in ordered
        if e.event_type == FILE_CREATE
        and _same_path(e.file_path, path)
        and _same_actor(e, download)
        and _between(e, download, execution)
    ]
    permission_changes = _permission_changes(path, download, execution, ordered)
    connections = [
        e
        for e in ordered
        if e.event_type == NETWORK_CONNECTION
        and _same_process(e, execution)
        and _in_window(e, execution, window)
        and is_external_ip(e.destination_ip)
    ]

    signals = []
    if file_creates:
        signals.append("file_create_observed")
    if permission_changes:
        signals.append("made_executable")
    if path.startswith(TEMPORARY_DIRECTORIES) or basename(path).startswith("."):
        signals.append("temporary_or_hidden_path")
    if connections:
        signals.append("external_connection_after_execution")

    evidence = [_evidence(download, f"DOWNLOAD: {basename(download.process)} wrote {path}")]
    evidence += [_evidence(e, f"file created: {path}") for e in file_creates]
    for event in permission_changes:
        if event.event_type == PROCESS_CREATE:
            evidence.append(_evidence(event, f"PERMISSION: {event.command_line}"))
        else:
            evidence.append(_evidence(event, f"PERMISSION: mode of {path} changed by chmod"))
    evidence.append(_evidence(execution, f"EXECUTION: {path} started"))
    evidence += [
        _evidence(e, f"NETWORK: {file_name(path)} connected to {e.destination_ip}:{e.destination_port}")
        for e in connections
    ]

    elapsed = _seconds_between(download, execution)
    tool = basename(download.process)
    reasoning = f"On {download.host}, user '{download.user}' downloaded {path} with {tool}"
    if permission_changes:
        reasoning += ", made it executable,"
    reasoning += f" and executed it {elapsed} seconds after the download."
    if connections:
        destinations = ", ".join(f"{e.destination_ip}:{e.destination_port}" for e in connections)
        reasoning += f" The executed file then connected to {destinations}."
    reasoning += (
        " Each step is common on its own; the sequence on one file is consistent with a downloaded "
        "payload being run and requires investigation. The destinations are not confirmed as malicious."
    )

    return _make_detection(
        PAYLOAD_EXECUTION,
        evidence,
        description="A file downloaded with curl/wget was executed on the same host by the same user.",
        severity=HIGH if permission_changes else MEDIUM,
        confidence=_confidence(PAYLOAD_WEIGHTS, signals, base=PAYLOAD_BASE_CONFIDENCE),
        host=download.host,
        user=download.user,
        source_ip=None,
        reasoning=reasoning,
        signals=[f"base: download command and execution of the same file (+{PAYLOAD_BASE_CONFIDENCE:.2f})"]
        + _describe_signals(PAYLOAD_WEIGHTS, signals, PAYLOAD_LABELS),
        details={
            "downloaded_path": path,
            "download_command": download.command_line,
            "download_event": download.event_id,
            "permission_events": [e.event_id for e in permission_changes],
            "execution_event": execution.event_id,
            "execution_parent_process": execution.parent_process,
            "network_events": [e.event_id for e in connections],
            "external_ips": _unique_in_order([e.destination_ip for e in connections]),
            "elapsed_seconds_download_to_execution": elapsed,
        },
        false_positives=PAYLOAD_FALSE_POSITIVES,
    )


# --- Engine -----------------------------------------------------------------


def run_detections(events: list[NormalizedEvent], config: DetectionConfig = DEFAULT_CONFIG) -> list[Detection]:
    """Run every detector and return detections ordered by first_seen."""
    detections = (
        detect_credential_attack(events, config)
        + detect_suspicious_powershell(events, config)
        + detect_payload_execution(events, config)
    )
    return sorted(detections, key=lambda detection: detection.first_seen)
