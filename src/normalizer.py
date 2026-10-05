"""Normalize raw, vendor-specific security events into one small common schema.

Each supported log source has its own parser that maps vendor field names
(``src_ip``, ``source_address``, ``SourceIp`` ...) onto the same normalized
fields. Detection and investigation logic can then be written once against the
normalized schema instead of once per vendor.

The schema is intentionally small and educational. It borrows the
principal/target idea from SIEM data models such as Google SecOps UDM, but it
is NOT UDM.
"""

from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

RawEvent = dict[str, Any]

# --- Normalized event types -------------------------------------------------

AUTHENTICATION = "AUTHENTICATION"
PROCESS_CREATE = "PROCESS_CREATE"
NETWORK_CONNECTION = "NETWORK_CONNECTION"
DNS_QUERY = "DNS_QUERY"
FILE_CREATE = "FILE_CREATE"
FILE_MODIFICATION = "FILE_MODIFICATION"

EVENT_TYPES = (
    AUTHENTICATION,
    PROCESS_CREATE,
    NETWORK_CONNECTION,
    DNS_QUERY,
    FILE_CREATE,
    FILE_MODIFICATION,
)

# --- Normalized result values -----------------------------------------------

SUCCESS = "SUCCESS"
FAILURE = "FAILURE"
ALLOWED = "ALLOWED"
BLOCKED = "BLOCKED"

# Values some products emit to mean "no value" (e.g. Windows uses "-").
_EMPTY_VALUES = (None, "", "-")


class UnsupportedEventError(ValueError):
    """Raised when a raw event comes from an unknown log source or event code."""


@dataclass
class NormalizedEvent:
    """Vendor-neutral representation of a single security event.

    Only ``event_id``, ``timestamp``, ``event_type``, ``vendor`` and
    ``raw_event`` are always present. Other fields are ``None`` when the
    event type or source does not provide them.

    ``principal`` describes the entity that initiated the action and
    ``target`` the entity acted upon. Their contents depend on the event type
    (see ``_build_principal_and_target``).
    """

    event_id: str
    timestamp: str  # ISO 8601, UTC, millisecond precision, e.g. 2026-09-14T09:41:03.000Z
    event_type: str
    vendor: str
    log_source: str
    principal: dict[str, Any] = field(default_factory=dict)
    target: dict[str, Any] = field(default_factory=dict)
    user: str | None = None
    host: str | None = None
    process: str | None = None
    parent_process: str | None = None
    process_id: int | None = None
    parent_process_id: int | None = None
    command_line: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    destination_port: int | None = None
    dns_query: str | None = None
    file_path: str | None = None
    result: str | None = None
    raw_event: RawEvent = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# --- Small value helpers ----------------------------------------------------


def _clean(value: Any) -> Any:
    """Return ``None`` for empty/placeholder values, otherwise the value."""
    if isinstance(value, str):
        value = value.strip()
    return None if value in _EMPTY_VALUES else value


def _to_int(value: Any) -> int | None:
    value = _clean(value)
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _strip_domain(account: Any) -> str | None:
    """``CORP\\mgarcia`` -> ``mgarcia``; plain names are returned unchanged."""
    account = _clean(account)
    if account is None:
        return None
    return str(account).rsplit("\\", 1)[-1]


def _short_hostname(name: Any) -> str | None:
    """``FIN-WS-07.corp.example.com`` -> ``FIN-WS-07``."""
    name = _clean(name)
    if name is None:
        return None
    return str(name).split(".", 1)[0]


def _format_utc(dt: datetime) -> str:
    dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _parse_iso(value: str) -> str:
    """Parse ISO 8601 strings, including a trailing ``Z``."""
    return _format_utc(datetime.fromisoformat(value.replace("Z", "+00:00")))


def _parse_naive_utc(value: str) -> str:
    """Parse ``YYYY-MM-DD HH:MM:SS[.fff]`` strings that are known to be UTC."""
    return _format_utc(datetime.fromisoformat(value).replace(tzinfo=timezone.utc))


def _parse_epoch_ms(value: int | float) -> str:
    return _format_utc(datetime.fromtimestamp(value / 1000, tz=timezone.utc))


def _event_id(raw: RawEvent) -> str:
    """Deterministic ID derived from the raw event content.

    The same raw event always gets the same ID, which keeps CLI output and
    tests reproducible.
    """
    canonical = json.dumps(raw, sort_keys=True).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()[:12]


# --- Per-source parsers -----------------------------------------------------
# Each parser returns a dict of normalized fields for one raw event.


def _parse_linux_sshd(raw: RawEvent) -> dict[str, Any]:
    """OpenSSH authentication logs (syslog, already split into fields)."""
    results = {"auth_success": SUCCESS, "auth_failure": FAILURE}
    if raw.get("event") not in results:
        raise UnsupportedEventError(f"unsupported sshd event: {raw.get('event')!r}")
    return {
        "vendor": "OpenSSH",
        "event_type": AUTHENTICATION,
        "timestamp": _parse_iso(raw["timestamp"]),
        "user": _clean(raw.get("user")),
        "host": _short_hostname(raw.get("host")),
        "source_ip": _clean(raw.get("src_ip")),
        "process": _clean(raw.get("program")),
        "process_id": _to_int(raw.get("pid")),
        "result": results[raw["event"]],
    }


def _parse_linux_edr(raw: RawEvent) -> dict[str, Any]:
    """Simulated Linux endpoint sensor (process, file and network events)."""
    event_types = {
        "process_exec": PROCESS_CREATE,
        "file_create": FILE_CREATE,
        "file_chmod": FILE_MODIFICATION,
        "network_connect": NETWORK_CONNECTION,
    }
    category = raw.get("event_category")
    if category not in event_types:
        raise UnsupportedEventError(f"unsupported linux_edr category: {category!r}")
    return {
        "vendor": "Simulated Linux EDR",
        "event_type": event_types[category],
        "timestamp": _parse_epoch_ms(raw["event_time"]),
        "user": _clean(raw.get("username")),
        "host": _short_hostname(raw.get("hostname")),
        "process": _clean(raw.get("exe_path")),
        "parent_process": _clean(raw.get("parent_exe_path")),
        "process_id": _to_int(raw.get("pid")),
        "parent_process_id": _to_int(raw.get("ppid")),
        "command_line": _clean(raw.get("cmdline")),
        "file_path": _clean(raw.get("target_path")),
        "source_ip": _clean(raw.get("local_ip")),
        "destination_ip": _clean(raw.get("remote_ip")),
        "destination_port": _to_int(raw.get("remote_port")),
    }


def _parse_network_firewall(raw: RawEvent) -> dict[str, Any]:
    """Simulated perimeter firewall connection log (timestamps in UTC)."""
    results = {"allow": ALLOWED, "deny": BLOCKED, "drop": BLOCKED}
    return {
        "vendor": "Simulated Firewall",
        "event_type": NETWORK_CONNECTION,
        "timestamp": _parse_naive_utc(raw["time"]),
        "source_ip": _clean(raw.get("source_address")),
        "destination_ip": _clean(raw.get("destination_address")),
        "destination_port": _to_int(raw.get("destination_port")),
        "result": results.get(str(raw.get("action", "")).lower()),
    }


def _parse_windows_security(raw: RawEvent) -> dict[str, Any]:
    """Windows Security log logon events (4624 success, 4625 failure)."""
    results = {4624: SUCCESS, 4625: FAILURE}
    event_code = _to_int(raw.get("EventID"))
    if event_code not in results:
        raise UnsupportedEventError(f"unsupported Windows Security EventID: {event_code!r}")
    return {
        "vendor": "Microsoft Windows",
        "event_type": AUTHENTICATION,
        "timestamp": _parse_iso(raw["TimeCreated"]),
        "user": _strip_domain(raw.get("TargetUserName")),
        "host": _short_hostname(raw.get("Computer")),
        "source_ip": _clean(raw.get("IpAddress")),
        "result": results[event_code],
    }


def _parse_sysmon(raw: RawEvent) -> dict[str, Any]:
    """Sysmon events 1 (process), 3 (network), 11 (file create), 22 (DNS)."""
    event_types = {
        1: PROCESS_CREATE,
        3: NETWORK_CONNECTION,
        11: FILE_CREATE,
        22: DNS_QUERY,
    }
    event_code = _to_int(raw.get("EventID"))
    if event_code not in event_types:
        raise UnsupportedEventError(f"unsupported Sysmon EventID: {event_code!r}")
    return {
        "vendor": "Microsoft Sysmon",
        "event_type": event_types[event_code],
        "timestamp": _parse_naive_utc(raw["UtcTime"]),
        "user": _strip_domain(raw.get("User")),
        "host": _short_hostname(raw.get("Computer")),
        "process": _clean(raw.get("Image")),
        "parent_process": _clean(raw.get("ParentImage")),
        "process_id": _to_int(raw.get("ProcessId")),
        "parent_process_id": _to_int(raw.get("ParentProcessId")),
        "command_line": _clean(raw.get("CommandLine")),
        "source_ip": _clean(raw.get("SourceIp")),
        "destination_ip": _clean(raw.get("DestinationIp")),
        "destination_port": _to_int(raw.get("DestinationPort")),
        "dns_query": _clean(raw.get("QueryName")),
        "file_path": _clean(raw.get("TargetFilename")),
    }


PARSERS: dict[str, Callable[[RawEvent], dict[str, Any]]] = {
    "linux_sshd": _parse_linux_sshd,
    "linux_edr": _parse_linux_edr,
    "network_firewall": _parse_network_firewall,
    "windows_security": _parse_windows_security,
    "sysmon": _parse_sysmon,
}


# --- Principal / target -----------------------------------------------------


def _build_principal_and_target(fields: dict[str, Any]) -> tuple[dict, dict]:
    """Assign normalized fields to the initiating (principal) and acted-upon
    (target) entities. Which fields belong where depends on the event type.

    For example, in AUTHENTICATION the source IP belongs to the principal while
    the user account and host being logged into are the target. In
    PROCESS_CREATE the parent process is the principal and the new process is
    the target.
    """
    event_type = fields["event_type"]
    get = fields.get

    if event_type == AUTHENTICATION:
        principal = {"ip": get("source_ip")}
        target = {"user": get("user"), "host": get("host")}
    elif event_type == PROCESS_CREATE:
        principal = {"user": get("user"), "host": get("host"), "process": get("parent_process")}
        target = {"process": get("process"), "command_line": get("command_line")}
    elif event_type == NETWORK_CONNECTION:
        principal = {
            "user": get("user"),
            "host": get("host"),
            "process": get("process"),
            "ip": get("source_ip"),
        }
        target = {"ip": get("destination_ip"), "port": get("destination_port")}
    elif event_type == DNS_QUERY:
        principal = {"user": get("user"), "host": get("host"), "process": get("process")}
        target = {"hostname": get("dns_query")}
    else:  # FILE_CREATE, FILE_MODIFICATION
        principal = {"user": get("user"), "host": get("host"), "process": get("process")}
        target = {"file_path": get("file_path")}

    def drop_empty(entity: dict) -> dict:
        return {key: value for key, value in entity.items() if value is not None}

    return drop_empty(principal), drop_empty(target)


# --- Public API -------------------------------------------------------------


def identify_source(raw: RawEvent) -> str:
    """Return the event's log source label, or raise if it is not supported.

    Like SIEM ingestion labels, every raw event carries a ``log_source`` that
    tells the pipeline which parser to use.
    """
    source = raw.get("log_source")
    if source not in PARSERS:
        raise UnsupportedEventError(f"unknown log_source: {source!r}")
    return source


def normalize_event(raw: RawEvent) -> NormalizedEvent:
    """Normalize one raw event. The original event is preserved unchanged
    (as a deep copy) in ``raw_event``."""
    source = identify_source(raw)
    fields = PARSERS[source](raw)
    principal, target = _build_principal_and_target(fields)
    return NormalizedEvent(
        event_id=_event_id(raw),
        log_source=source,
        principal=principal,
        target=target,
        raw_event=copy.deepcopy(raw),
        **fields,
    )


def normalize_events(
    raw_events: list[RawEvent],
) -> tuple[list[NormalizedEvent], list[tuple[RawEvent, str]]]:
    """Normalize many events and sort them chronologically.

    Returns ``(normalized, rejected)``. Rejected events are returned with the
    reason instead of being silently dropped, so nothing disappears unnoticed.
    """
    normalized: list[NormalizedEvent] = []
    rejected: list[tuple[RawEvent, str]] = []
    for raw in raw_events:
        try:
            normalized.append(normalize_event(raw))
        except (KeyError, ValueError, TypeError) as exc:
            rejected.append((raw, f"{type(exc).__name__}: {exc}"))
    normalized.sort(key=lambda event: event.timestamp)
    return normalized, rejected
