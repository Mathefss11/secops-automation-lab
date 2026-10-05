"""SecOps Automation Lab - CLI.

Loads simulated security telemetry, normalizes it, prints a chronological
timeline, runs behavioral detections and enriches them with MITRE ATT&CK
mappings and threat intelligence. Normalized events and detections can be
inspected individually or exported to JSON.

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
from src.normalizer import NormalizedEvent, normalize_events
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


def print_banner() -> None:
    line = "=" * LINE_WIDTH
    print(line)
    print("SECOPS AUTOMATION LAB".center(LINE_WIDTH))
    print("Normalization, detection and enrichment".center(LINE_WIDTH))
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


def inspect(input_path: Path, record_id: str, choice: str) -> int:
    """Print the normalized event or (enriched) detection with this ID as JSON."""
    events, _ = normalize_events(load_events(input_path))
    records: dict[str, NormalizedEvent | EnrichedDetection] = {event.event_id: event for event in events}
    detections = [d for d in run_detections(events) if d.detection_id == record_id]
    if detections:  # only enrich (and possibly query a provider) when a detection was asked for
        intel, disabled_reason = build_threat_intel(choice)
        records[record_id] = enrich_detections(detections, intel, disabled_reason)[0]
    if record_id not in records:
        print(f"[!] No event or detection with id {record_id}", file=sys.stderr)
        return 1
    print(json.dumps(records[record_id].to_dict(), indent=2))
    return 0


def export(path: Path, records: list[dict]) -> None:
    path.parent.mkdir(exist_ok=True)
    path.write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")
    print(f"[+] Written to {path.relative_to(PROJECT_ROOT)}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Normalize simulated security telemetry, detect and enrich.")
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT, help="raw events JSON file")
    parser.add_argument(
        "--inspect", metavar="ID", help="print one normalized event (event ID) or detection (DET-...) in full"
    )
    parser.add_argument("--no-timeline", action="store_true", help="skip the event timeline, show detections only")
    parser.add_argument("--export", action="store_true", help="write normalized events and detections to output/")
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

    if not args.no_timeline:
        print_timeline(events)

    print("\n[+] Running detections...")
    detections = run_detections(events)

    intel, disabled_reason = build_threat_intel(args.threat_intel)
    print(describe_provider(intel, disabled_reason))
    if intel is None:
        print("    Detections and ATT&CK mapping still run.")
    enriched_detections = enrich_detections(detections, intel, disabled_reason)
    print_detections(enriched_detections)
    if intel is not None:
        print(f"[+] Threat intel: {intel.provider_calls} provider lookup(s), {intel.cache_hits} served from cache")

    if args.export:
        print()
        export(DEFAULT_EXPORT, [event.to_dict() for event in events])
        export(DETECTIONS_EXPORT, [enriched.to_dict() for enriched in enriched_detections])

    print("\nTip: python main.py --inspect <event-id | DET-id> shows the full record.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
