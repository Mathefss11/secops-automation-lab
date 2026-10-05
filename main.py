"""SecOps Automation Lab - CLI.

Loads simulated security telemetry, normalizes it, prints a chronological
timeline and runs behavioral detections. Normalized events and detections can
be inspected individually or exported to JSON.
"""

from __future__ import annotations

import argparse
import json
import sys
import textwrap
from pathlib import Path

from src.detection_engine import Detection, run_detections
from src.normalizer import NormalizedEvent, normalize_events

PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_INPUT = PROJECT_ROOT / "data" / "security_events.json"
DEFAULT_EXPORT = PROJECT_ROOT / "output" / "normalized_events.json"
DETECTIONS_EXPORT = PROJECT_ROOT / "output" / "detections.json"
LINE_WIDTH = 72

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


def _wrap(text: str) -> str:
    return textwrap.fill(text, width=LINE_WIDTH, initial_indent="    ", subsequent_indent="    ")


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


def print_banner() -> None:
    line = "=" * LINE_WIDTH
    print(line)
    print("SECOPS AUTOMATION LAB".center(LINE_WIDTH))
    print("Normalization and behavioral detection".center(LINE_WIDTH))
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


def print_detections(detections: list[Detection]) -> None:
    line = "=" * LINE_WIDTH
    print(f"\n{line}\n{'DETECTIONS'.center(LINE_WIDTH)}\n{line}\n")
    if not detections:
        print("No detections.")
        return
    for detection in detections:
        print(format_detection(detection))
        print("-" * LINE_WIDTH)
        print()
    print(f"[+] {len(detections)} detection(s)")


def inspect(input_path: Path, record_id: str) -> int:
    """Print the normalized event or detection with this ID as JSON."""
    events, _ = normalize_events(load_events(input_path))
    records: dict[str, NormalizedEvent | Detection] = {event.event_id: event for event in events}
    records.update({detection.detection_id: detection for detection in run_detections(events)})
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
    parser = argparse.ArgumentParser(description="Normalize simulated security telemetry and run detections.")
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT, help="raw events JSON file")
    parser.add_argument(
        "--inspect", metavar="ID", help="print one normalized event (event ID) or detection (DET-...) in full"
    )
    parser.add_argument("--no-timeline", action="store_true", help="skip the event timeline, show detections only")
    parser.add_argument("--export", action="store_true", help="write normalized events and detections to output/")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if args.inspect:
        return inspect(args.input, args.inspect)

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
    print_detections(detections)

    if args.export:
        print()
        export(DEFAULT_EXPORT, [event.to_dict() for event in events])
        export(DETECTIONS_EXPORT, [detection.to_dict() for detection in detections])

    print("\nTip: python main.py --inspect <event-id | DET-id> shows the full record.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
