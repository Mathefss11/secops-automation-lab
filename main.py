"""SecOps Automation Lab - Phase 1 CLI.

Loads simulated security telemetry, normalizes it and prints a chronological
timeline. Normalized events can be inspected individually or exported to JSON.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from src.normalizer import NormalizedEvent, normalize_events

PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_INPUT = PROJECT_ROOT / "data" / "security_events.json"
DEFAULT_EXPORT = PROJECT_ROOT / "output" / "normalized_events.json"

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


def print_banner() -> None:
    line = "=" * 60
    print(line)
    print("SECOPS AUTOMATION LAB".center(60))
    print("Phase 1: telemetry normalization".center(60))
    print(line)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Normalize simulated security telemetry.")
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT, help="raw events JSON file")
    parser.add_argument("--inspect", metavar="EVENT_ID", help="print one normalized event in full, including raw_event")
    parser.add_argument("--export", action="store_true", help=f"write normalized events to {DEFAULT_EXPORT.relative_to(PROJECT_ROOT)}")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if args.inspect:
        raw_events = load_events(args.input)
        events, _ = normalize_events(raw_events)
        for event in events:
            if event.event_id == args.inspect:
                print(json.dumps(event.to_dict(), indent=2))
                return 0
        print(f"[!] No event with id {args.inspect}", file=sys.stderr)
        return 1

    print_banner()
    print("\n[+] Loading security telemetry...")
    raw_events = load_events(args.input)
    print(f"[+] {len(raw_events)} events loaded from {args.input.name}")

    print("\n[+] Normalizing events...")
    events, rejected = normalize_events(raw_events)
    print(f"[+] {len(events)} events normalized")
    for raw, reason in rejected:
        print(f"[!] Rejected event (log_source={raw.get('log_source')!r}): {reason}")

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

    if args.export:
        DEFAULT_EXPORT.parent.mkdir(exist_ok=True)
        DEFAULT_EXPORT.write_text(
            json.dumps([event.to_dict() for event in events], indent=2) + "\n", encoding="utf-8"
        )
        print(f"\n[+] Normalized events written to {DEFAULT_EXPORT.relative_to(PROJECT_ROOT)}")

    print("\nTip: python main.py --inspect <id> shows a full normalized event.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
