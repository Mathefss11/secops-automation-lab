"""Map detections to MITRE ATT&CK techniques, only when the evidence supports it.

ATT&CK describes adversary behavior. A mapping says "the observed activity
matches this documented behavior". It does NOT prove malicious intent, and
ATT&CK is not a severity scale.

Every mapping is conditional on specific evidence in the detection, and its
``reason`` cites that evidence. Technique IDs and names were checked against
https://attack.mitre.org on 2026-10-05.
"""

from __future__ import annotations

import ipaddress
from dataclasses import asdict, dataclass
from typing import Any, Callable

from src.command_analysis import (
    basename,
    decode_encoded_command,
    file_name,
    get_encoded_command,
    get_url_hosts,
    has_hidden_window,
)
from src.detection_engine import (
    CREDENTIAL_ATTACK,
    PAYLOAD_EXECUTION,
    SUSPICIOUS_POWERSHELL,
    Detection,
    is_external_ip,
)

TECHNIQUE_NAMES = {
    "T1110": "Brute Force",
    "T1059.001": "Command and Scripting Interpreter: PowerShell",
    "T1059.004": "Command and Scripting Interpreter: Unix Shell",
    "T1027.010": "Obfuscated Files or Information: Command Obfuscation",
    "T1564.003": "Hide Artifacts: Hidden Window",
    "T1105": "Ingress Tool Transfer",
}

UNIX_SHELLS = {"sh", "bash", "dash", "zsh", "ash", "ksh"}


@dataclass(frozen=True)
class AttackTechnique:
    technique_id: str
    technique_name: str
    reason: str

    @property
    def url(self) -> str:
        return "https://attack.mitre.org/techniques/" + self.technique_id.replace(".", "/") + "/"

    def to_dict(self) -> dict[str, Any]:
        return {**asdict(self), "url": self.url}


def _technique(technique_id: str, reason: str) -> AttackTechnique:
    return AttackTechnique(technique_id, TECHNIQUE_NAMES[technique_id], reason)


def _is_external_host(host: str) -> bool:
    """URL host is external: a non-internal IP, or a hostname other than localhost."""
    if host.lower() == "localhost":
        return False
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return True  # a hostname; we cannot resolve it (and must not), so treat as external
    return is_external_ip(host)


# --- Per-detection mappings -------------------------------------------------


def map_credential_attack(detection: Detection) -> list[AttackTechnique]:
    details = detection.details
    reason = (
        f"{details['failed_attempts']} failed authentication attempts against "
        f"{len(details['targeted_accounts'])} accounts from {detection.source_ip} were followed by a "
        f"successful authentication as '{details['authenticated_account']}'. Mapped to the parent "
        f"technique only: the telemetry cannot show whether one password was tried across accounts "
        f"(T1110.003 Password Spraying) or several passwords per account (T1110.001 Password Guessing)."
    )
    return [_technique("T1110", reason)]


def map_suspicious_powershell(detection: Detection) -> list[AttackTechnique]:
    details = detection.details
    command_line = details.get("command_line")
    parent = file_name(details.get("parent_process")) or "an unknown parent"
    techniques = [
        _technique(
            "T1059.001",
            f"{parent} started {file_name(details.get('process'))} (PID {details.get('process_id')}); "
            f"the detection correlates that PowerShell process with the follow-on activity.",
        )
    ]

    encoded = get_encoded_command(command_line)
    if encoded:
        reason = "The PowerShell command line passes its script as a Base64 -EncodedCommand value"
        if decode_encoded_command(encoded):
            reason += " (decoded for analyst review, not executed)"
        techniques.append(_technique("T1027.010", reason + "."))

    if has_hidden_window(command_line):
        techniques.append(
            _technique("T1564.003", "The PowerShell command line requests a hidden window (-WindowStyle Hidden).")
        )

    # Only PowerShell's own connections count here, not those of the file it started.
    if details.get("powershell_external_ips") and details.get("created_files"):
        reason = (
            f"The same PowerShell process connected to {', '.join(details['powershell_external_ips'])} and created "
            f"{', '.join(details['created_files'])}."
        )
        if details.get("executed_files"):
            reason += " The created file was then executed."
        techniques.append(_technique("T1105", reason))
    return techniques


def map_payload_execution(detection: Detection) -> list[AttackTechnique]:
    details = detection.details
    techniques = []

    external_sources = [host for host in get_url_hosts(details.get("download_command")) if _is_external_host(host)]
    if external_sources:
        techniques.append(
            _technique(
                "T1105",
                f"'{details['download_command']}' downloaded a file from {', '.join(external_sources)} to "
                f"{details['downloaded_path']}, which was later executed on {detection.host}.",
            )
        )

    parent = details.get("execution_parent_process")
    if basename(parent) in UNIX_SHELLS:
        techniques.append(
            _technique(
                "T1059.004",
                f"{details['downloaded_path']} was executed from a Unix shell ({parent}) "
                f"as user '{detection.user}'.",
            )
        )
    return techniques


MAPPERS: dict[str, Callable[[Detection], list[AttackTechnique]]] = {
    CREDENTIAL_ATTACK: map_credential_attack,
    SUSPICIOUS_POWERSHELL: map_suspicious_powershell,
    PAYLOAD_EXECUTION: map_payload_execution,
}


def map_detection(detection: Detection) -> list[AttackTechnique]:
    """ATT&CK techniques supported by this detection's evidence (no duplicates).
    Unknown detection types get no mapping rather than a guess."""
    mapper = MAPPERS.get(detection.name)
    if mapper is None:
        return []
    unique: dict[str, AttackTechnique] = {}
    for technique in mapper(detection):
        unique.setdefault(technique.technique_id, technique)
    return list(unique.values())
