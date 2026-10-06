"""SecOps Automation Lab - CLI.

Loads simulated security telemetry, normalizes it, prints a chronological
timeline, runs behavioral detections, enriches them with MITRE ATT&CK
mappings and threat intelligence, scores incident risk and evaluates a
SOAR-style playbook. Events, detections and incidents can be inspected
individually or exported to JSON.

Every playbook action is SIMULATED: nothing is blocked, disabled or isolated.

By default threat intelligence comes from an offline mock provider: no network
requests are made unless a real provider is explicitly selected.
"""

from __future__ import annotations

import argparse
import json
import sys
import textwrap
from pathlib import Path

from src.detection_engine import Detection, run_detections
from src.enrichment import EnrichedDetection, enrich_detections
from src.incident import SIMULATION_DISCLAIMER, Incident, create_incidents
from src.normalizer import NormalizedEvent, normalize_events
from src.playbook import run_playbooks
from src.threat_intel import (
    ABUSEIPDB_API_KEY_ENV,
    AbuseIPDBProvider,
    CachedThreatIntel,
    MissingApiKeyError,
    MockThreatIntelProvider,
    ThreatIntelResult,
)

PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_INPUT = PROJECT_ROOT / "data" / "security_events.json"
DEFAULT_EXPORT = PROJECT_ROOT / "output" / "normalized_events.json"
DETECTIONS_EXPORT = PROJECT_ROOT / "output" / "detections.json"
INCIDENTS_DIR = PROJECT_ROOT / "output" / "incidents"
LINE_WIDTH = 72

THREAT_INTEL_CHOICES = ("mock", "abuseipdb")

# Which normalized fields to show in the timeline, per event type.
SUMMARY_FIELDS = {
    "AUTHENTICATION": ("user", "host", "source_ip", "result"),
    "PROCESS_CREATE": ("user", "host", "parent_process", "command_line"),
    "NETWORK_CONNECTION": ("host", "process", "source_ip", "destination_ip", "destination_port", "result"),
    "DNS_QUERY": ("host", "process", "dns_query"),
    "FILE_CREATE": ("host", "process", "file_path"),
    "FILE_MODIFICATION": ("host", "process", "file_path"),
}


def load_events(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as fh:
        events = json.load(fh)
    if not isinstance(events, list):
        raise ValueError(f"{path} must contain a JSON array of events")
    return events


def format_event(event: NormalizedEvent) -> str:
    date, time = event.timestamp[:10], event.timestamp[11:19]
    source = f"[{event.log_source}]"
    header = f"{date} {time}  {event.event_type:<18}  {source:<18}  id={event.event_id}"
    details = []
    for name in SUMMARY_FIELDS.get(event.event_type, ()):
        value = getattr(event, name)
        if value is not None:
            details.append(f"    {name}={value}")
    return "\n".join([header, *details])


def _wrap(text: str, indent: str = "    ") -> str:
    return textwrap.fill(text, width=LINE_WIDTH, initial_indent=indent, subsequent_indent=indent)


def format_detection(detection: Detection) -> str:
    lines = [
        f"[{detection.severity}] {detection.name}",
        "",
        f"    Detection ID: {detection.detection_id}",
        f"    Host:         {detection.host or '-'}",
        f"    User:         {detection.user or '-'}",
    ]
    if detection.source_ip:
        lines.append(f"    Source IP:    {detection.source_ip}")
    lines += [
        f"    Confidence:   {detection.confidence:.2f}",
        f"    First seen:   {detection.first_seen}",
        f"    Last seen:    {detection.last_seen}",
        "",
        "  Reasoning:",
        _wrap(detection.reasoning),
        "",
        "  Contributing signals:",
        *(f"    + {signal}" for signal in detection.signals),
        "",
        "  Evidence:",
        *(f"    - {item.event_id}  {item.timestamp[11:23]}  {item.description}" for item in detection.evidence),
    ]
    decoded = detection.details.get("decoded_command")
    if decoded:
        # Not wrapped: line breaks inside code would change how it reads.
        lines += ["", "  Decoded -EncodedCommand (analyst context only, NOT executed):", f"    {decoded}"]
    lines += ["", "  Possible false positives:", *(f"    * {fp}" for fp in detection.false_positives)]
    return "\n".join(lines)


def format_threat_intel_result(result: ThreatIntelResult) -> list[str]:
    label = "  [SIMULATED]" if result.simulated else ""
    lines = [f"    Indicator:  {result.indicator}{label}", f"    Reputation: {result.reputation}"]
    if result.error:
        lines.append(f"    Lookup:     failed - {result.error}")
    else:
        confidence = f"{result.confidence:.2f}" if result.confidence is not None else "-"
        lines += [f"    Confidence: {confidence}", f"    Tags:       {', '.join(result.tags) or '-'}"]
        note = result.details.get("note")
        if note:
            lines.append(f"    Note:       {note}")
    lines.append(f"    Source:     {result.source}")
    return lines


def format_enrichment(enriched: EnrichedDetection) -> str:
    lines = ["", "  MITRE ATT&CK:"]
    if not enriched.mitre_techniques:
        lines.append("    (no technique mapping supported by the evidence)")
    for technique in enriched.mitre_techniques:
        lines.append(f"    {technique.technique_id} - {technique.technique_name}")
        lines.append(_wrap("Reason: " + technique.reason, indent="      "))

    lines += ["", "  Threat Intelligence (context, not proof of compromise):", _wrap("Status: " + enriched.threat_intel_status)]
    if not enriched.threat_intel:
        lines.append("    (no indicators enriched)")
    for index, result in enumerate(enriched.threat_intel):
        if index:
            lines.append("")
        lines += format_threat_intel_result(result)
    return "\n".join(lines)


def format_incident(incident: Incident) -> str:
    detection = incident.detection
    enriched = incident.enriched_detection
    lines = [
        f"[{incident.risk_level}] {incident.title}",
        "",
        f"    Incident ID:          {incident.incident_id}",
        f"    Created at:           {incident.created_at}",
        f"    Detection:            {detection.name} ({detection.detection_id})",
        f"    Host:                 {detection.host or '-'}",
        f"    User:                 {detection.user or '-'}",
    ]
    if detection.source_ip:
        lines.append(f"    Source IP:            {detection.source_ip}")
    lines += [
        f"    Detection severity:   {detection.severity}",
        f"    Detection confidence: {detection.confidence:.2f}",
        f"    Risk score:           {incident.risk_score}/100 ({incident.risk_level})",
    ]
    if incident.risk.level_note:
        lines.append(_wrap("Note: " + incident.risk.level_note))
    lines += ["", "  Risk contributors:"]
    for contributor in incident.risk_contributors:
        wrapped = textwrap.wrap(f"{contributor.category}: {contributor.reason}", width=LINE_WIDTH - 10)
        lines.append(f"    +{contributor.points:<3}  {wrapped[0]}")
        lines += [f"          {line}" for line in wrapped[1:]]

    techniques = ", ".join(f"{t.technique_id} {t.technique_name}" for t in enriched.mitre_techniques) or "-"
    lines += ["", "  MITRE ATT&CK:", _wrap(techniques)]
    lines += ["", "  Threat Intelligence:"]
    if not enriched.threat_intel:
        lines.append(f"    {enriched.threat_intel_status}")
    for result in enriched.threat_intel:
        # The source name itself says "(simulated)" for mock data.
        lines.append(f"    {result.indicator}: {result.reputation} - {result.source}")

    lines += ["", "  Playbook (simulated - no real system is changed):"]
    for action in incident.playbook_actions:
        approval = "  (needs analyst approval)" if action.requires_approval else ""
        lines.append(f"    [SIMULATED ACTION] {action.action_type}: {action.description}{approval}")
    return "\n".join(lines)


def print_banner() -> None:
    line = "=" * LINE_WIDTH
    print(line)
    print("SECOPS AUTOMATION LAB".center(LINE_WIDTH))
    print("Detection, enrichment and simulated response".center(LINE_WIDTH))
    print(line)


def print_timeline(events: list[NormalizedEvent]) -> None:
    print("\nTimeline (UTC):\n")
    for event in events:
        print(format_event(event))
        print()

    counts: dict[str, int] = {}
    for event in events:
        counts[event.event_type] = counts.get(event.event_type, 0) + 1
    print("Event types:")
    for event_type, count in sorted(counts.items()):
        print(f"    {event_type:<18} {count}")


def print_detections(enriched_detections: list[EnrichedDetection]) -> None:
    line = "=" * LINE_WIDTH
    print(f"\n{line}\n{'DETECTIONS'.center(LINE_WIDTH)}\n{line}\n")
    if not enriched_detections:
        print("No detections.")
        return
    for enriched in enriched_detections:
        print(format_detection(enriched.detection))
        print(format_enrichment(enriched))
        print("-" * LINE_WIDTH)
        print()
    print(f"[+] {len(enriched_detections)} detection(s)")


def print_incidents(incidents: list[Incident]) -> None:
    line = "=" * LINE_WIDTH
    print(f"\n{line}\n{'INCIDENTS'.center(LINE_WIDTH)}\n{line}\n")
    print(_wrap(SIMULATION_DISCLAIMER, indent=""))
    print()
    if not incidents:
        print("No incidents.")
        return
    for incident in incidents:
        print(format_incident(incident))
        print("-" * LINE_WIDTH)
        print()
    print(f"[+] {len(incidents)} incident(s)")


def build_threat_intel(choice: str) -> tuple[CachedThreatIntel | None, str | None]:
    """Return ``(intel, None)`` or ``(None, reason)`` when the provider cannot be used.

    Only the mock provider is used unless the user explicitly asks for another.
    """
    if choice == "mock":
        return CachedThreatIntel(MockThreatIntelProvider()), None
    try:
        return CachedThreatIntel(AbuseIPDBProvider.from_environment()), None
    except MissingApiKeyError:
        return None, f"{ABUSEIPDB_API_KEY_ENV} is not set, so AbuseIPDB was NOT queried"


def describe_provider(intel: CachedThreatIntel | None, disabled_reason: str | None) -> str:
    if intel is None:
        return f"[!] Threat intelligence disabled: {disabled_reason}."
    if intel.provider.simulated:
        return f"[+] Threat intelligence: {intel.provider.name} - offline, no network requests"
    return (
        f"[!] Threat intelligence: {intel.provider.name} (REAL external API). Only public IPs from detections\n"
        f"    are sent to the provider's API; no other host is contacted."
    )


def lookup_single_ip(choice: str, ip: str) -> int:
    intel, disabled_reason = build_threat_intel(choice)
    print(describe_provider(intel, disabled_reason))
    if intel is None:
        return 2
    print()
    print("\n".join(format_threat_intel_result(intel.lookup_ip(ip))))
    return 0


def build_incidents(enriched_detections: list[EnrichedDetection]) -> list[Incident]:
    """Risk engine + simulated playbook for every enriched detection."""
    return run_playbooks(create_incidents(enriched_detections))


def inspect(input_path: Path, record_id: str, choice: str) -> int:
    """Print the normalized event, enriched detection or incident with this ID as JSON."""
    events, _ = normalize_events(load_events(input_path))
    records: dict[str, dict] = {event.event_id: event.to_dict() for event in events}
    # Only enrich (and possibly query a provider) when a detection or incident was asked for.
    if record_id not in records and record_id.startswith(("DET-", "INC-")):
        intel, disabled_reason = build_threat_intel(choice)
        enriched_detections = enrich_detections(run_detections(events), intel, disabled_reason)
        for enriched in enriched_detections:
            records[enriched.detection.detection_id] = enriched.to_dict()
        for incident in build_incidents(enriched_detections):
            records[incident.incident_id] = incident.to_report()
    if record_id not in records:
        print(f"[!] No event, detection or incident with id {record_id}", file=sys.stderr)
        return 1
    print(json.dumps(records[record_id], indent=2))
    return 0


def export(path: Path, records: list[dict] | dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")
    print(f"[+] Written to {path.relative_to(PROJECT_ROOT)}")


def export_incidents(incidents: list[Incident]) -> None:
    """One report per incident. File names are the deterministic incident IDs,
    so incidents never overwrite each other."""
    for incident in incidents:
        export(INCIDENTS_DIR / f"{incident.incident_id}.json", incident.to_report())


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Normalize simulated security telemetry, detect, enrich, score risk and evaluate simulated playbooks.")
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT, help="raw events JSON file")
    parser.add_argument(
        "--inspect", metavar="ID", help="print one normalized event, detection (DET-...) or incident (INC-...) in full"
    )
    parser.add_argument("--no-timeline", action="store_true", help="skip the event timeline")
    parser.add_argument(
        "--incidents-only", action="store_true", help="show only incident summaries (no timeline or detection details)"
    )
    parser.add_argument(
        "--export", action="store_true", help="write normalized events, detections and incident reports to output/"
    )
    parser.add_argument(
        "--threat-intel",
        choices=THREAT_INTEL_CHOICES,
        default="mock",
        help="threat-intelligence provider (default: mock, offline). 'abuseipdb' makes real API "
        f"requests and needs {ABUSEIPDB_API_KEY_ENV}",
    )
    parser.add_argument(
        "--lookup-ip", metavar="IP", help="look up a single IP with the selected provider and exit"
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if args.lookup_ip:
        return lookup_single_ip(args.threat_intel, args.lookup_ip)
    if args.inspect:
        return inspect(args.input, args.inspect, args.threat_intel)

    print_banner()
    print("\n[+] Loading security telemetry...")
    raw_events = load_events(args.input)
    print(f"[+] {len(raw_events)} events loaded from {args.input.name}")

    print("\n[+] Normalizing events...")
    events, rejected = normalize_events(raw_events)
    print(f"[+] {len(events)} events normalized")
    for raw, reason in rejected:
        print(f"[!] Rejected event (log_source={raw.get('log_source')!r}): {reason}")

    if not (args.no_timeline or args.incidents_only):
        print_timeline(events)

    print("\n[+] Running detections...")
    detections = run_detections(events)

    intel, disabled_reason = build_threat_intel(args.threat_intel)
    print(describe_provider(intel, disabled_reason))
    if intel is None:
        print("    Detections and ATT&CK mapping still run.")
    enriched_detections = enrich_detections(detections, intel, disabled_reason)
    if args.incidents_only:
        print(f"[+] {len(detections)} detection(s)")
    else:
        print_detections(enriched_detections)
    if intel is not None:
        print(f"[+] Threat intel: {intel.provider_calls} provider lookup(s), {intel.cache_hits} served from cache")

    print("\n[+] Scoring risk and evaluating playbooks...")
    incidents = build_incidents(enriched_detections)
    print_incidents(incidents)

    if args.export:
        print()
        export(DEFAULT_EXPORT, [event.to_dict() for event in events])
        export(DETECTIONS_EXPORT, [enriched.to_dict() for enriched in enriched_detections])
        export_incidents(incidents)

    print("\nTip: python main.py --inspect <event-id | DET-id | INC-id> shows the full record.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
