#!/usr/bin/env python3
"""
PurpleTrace — lab-based attack simulation and defensive detection-validation toolkit.

PurpleTrace never executes a real technique. `run-scenario` only *writes synthetic,
clearly-labelled JSON log lines* that mimic the shape of real EDR/SIEM telemetry for
a given MITRE ATT&CK technique, so you can test whether your detection rules would
have caught the real thing. `detect` then runs sample detection logic against those
(or your real) events and reports matches.

See README.md for scenario descriptions, limitations, and defender investigation notes.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

DEFAULT_SCENARIOS = Path(__file__).parent / "scenarios.yaml"
DEFAULT_RULES = Path(__file__).parent / "detection_rules.yaml"


# --------------------------------------------------------------------------
# Scenario generation (synthetic, benign events only)
# --------------------------------------------------------------------------

def load_scenarios(path: Path = DEFAULT_SCENARIOS) -> dict[str, dict]:
    data = yaml.safe_load(path.read_text())
    return {s["id"]: s for s in data["scenarios"]}


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def generate_events(scenario_id: str, start: datetime, host: str = "lab-host-01") -> list[dict]:
    """Generate the synthetic event list for one scenario. All events carry
    simulated=True and a scenario_id so they're unambiguous in any pipeline."""
    base = {"simulated": True, "scenario_id": scenario_id, "host": host}

    if scenario_id == "T1087-enum":
        events = []
        cmds = ["net user", "net user /domain", "net group",
                "net group \"Domain Admins\" /domain", "net localgroup administrators", "net user jdoe"]
        for i, cmd in enumerate(cmds):
            events.append({
                **base, "event_type": "process_creation",
                "ts": _iso(start + timedelta(seconds=i * 20)),
                "user": "jdoe", "parent_process": "cmd.exe",
                "process": "net.exe", "command_line": cmd,
            })
        return events

    if scenario_id == "T1110-bruteforce":
        events = []
        for i in range(12):
            events.append({
                **base, "event_type": "auth_failure",
                "ts": _iso(start + timedelta(seconds=i * 5)),
                "user": "svc_backup", "source_ip": "203.0.113.77",  # TEST-NET-3, reserved for docs/examples
                "reason": "bad_password",
            })
        return events

    if scenario_id == "T1059-susproc":
        encoded = "V3JpdGUtT3V0cHV0IFB1cnBsZVRyYWNlLVNpbXVsYXRlZA=="  # base64("Write-Output PurpleTrace-Simulated")
        events = []
        for i, parent in enumerate(["winword.exe", "excel.exe", "outlook.exe"]):
            events.append({
                **base, "event_type": "process_creation",
                "ts": _iso(start + timedelta(seconds=i * 10)),
                "user": "jdoe", "parent_process": parent,
                "process": "powershell.exe",
                "command_line": f"powershell.exe -NoP -NonI -W Hidden -Enc {encoded}",
            })
        return events

    if scenario_id == "T1003-credaccess":
        return [
            {**base, "event_type": "file_access", "ts": _iso(start),
             "user": "jdoe", "process": "notepad.exe",
             "path": "/etc/shadow", "access_type": "read"},
            {**base, "event_type": "file_access", "ts": _iso(start + timedelta(seconds=5)),
             "user": "jdoe", "process": "notepad.exe",
             "path": r"C:\Windows\System32\config\SAM", "access_type": "read"},
        ]

    raise ValueError(f"Unknown scenario id: {scenario_id!r}")


def run_scenario(scenario_id: str, scenarios: dict[str, dict], out_path: Path) -> list[dict]:
    if scenario_id not in scenarios:
        raise ValueError(f"Unknown scenario id: {scenario_id!r} (see scenarios.yaml)")
    start = datetime.now(timezone.utc)
    events = generate_events(scenario_id, start)
    with out_path.open("a") as fh:
        for ev in events:
            fh.write(json.dumps(ev) + "\n")
    return events


# --------------------------------------------------------------------------
# Detection logic (simple, transparent rule engine)
# --------------------------------------------------------------------------

def load_rules(path: Path = DEFAULT_RULES) -> list[dict]:
    return yaml.safe_load(path.read_text())["rules"]


def load_events(path: Path) -> list[dict]:
    events = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if line:
            events.append(json.loads(line))
    return events


def _field_matches(event: dict, field: str, condition: dict) -> bool:
    value = str(event.get(field, ""))
    if "equals" in condition:
        return value == condition["equals"]
    if "in" in condition:
        return value in condition["in"]
    if "contains" in condition:
        return condition["contains"].lower() in value.lower()
    if "contains_any" in condition:
        return any(c.lower() in value.lower() for c in condition["contains_any"])
    return False


def _event_matches_conditions(event: dict, conditions: dict) -> bool:
    return all(_field_matches(event, field, cond) for field, cond in conditions.items())


def evaluate_rule(rule: dict, events: list[dict]) -> list[dict]:
    """Return a list of alert dicts for this rule against the given events."""
    candidates = [
        e for e in events
        if e.get("event_type") == rule["event_type"] and _event_matches_conditions(e, rule.get("conditions", {}))
    ]
    if not candidates:
        return []

    if rule["kind"] == "match":
        return [
            {"rule_id": rule["id"], "rule_name": rule["name"], "mitre": rule.get("mitre"),
             "matched_event": e}
            for e in candidates
        ]

    if rule["kind"] == "threshold":
        groups: dict[tuple, list[dict]] = {}
        for e in candidates:
            key = tuple(e.get(f) for f in rule["group_by"])
            groups.setdefault(key, []).append(e)
        alerts = []
        window = timedelta(minutes=rule["window_minutes"])
        for key, group_events in groups.items():
            group_events.sort(key=lambda e: e["ts"])
            times = [datetime.strptime(e["ts"], "%Y-%m-%dT%H:%M:%SZ") for e in group_events]
            # sliding window: count events within `window` of each other, starting from the first
            if len(times) >= rule["min_count"] and (times[-1] - times[0]) <= window:
                alerts.append({
                    "rule_id": rule["id"], "rule_name": rule["name"], "mitre": rule.get("mitre"),
                    "group_key": dict(zip(rule["group_by"], key)),
                    "matched_count": len(group_events),
                    "window_minutes": rule["window_minutes"],
                    "first_event": group_events[0], "last_event": group_events[-1],
                })
        return alerts

    raise ValueError(f"Unknown rule kind: {rule['kind']!r}")


def run_detection(events: list[dict], rules: list[dict]) -> list[dict]:
    alerts = []
    for rule in rules:
        alerts.extend(evaluate_rule(rule, events))
    return alerts


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="purpletrace", description="Lab attack simulation & detection validation.")
    sub = p.add_subparsers(dest="command", required=True)

    p_run = sub.add_parser("run-scenario", help="Generate synthetic benign events for one scenario.")
    p_run.add_argument("scenario_id")
    p_run.add_argument("--scenarios", type=Path, default=DEFAULT_SCENARIOS)
    p_run.add_argument("--out", type=Path, required=True)

    p_list = sub.add_parser("list-scenarios", help="List available scenarios.")
    p_list.add_argument("--scenarios", type=Path, default=DEFAULT_SCENARIOS)

    p_det = sub.add_parser("detect", help="Run detection rules against an events file.")
    p_det.add_argument("--events", type=Path, required=True)
    p_det.add_argument("--rules", type=Path, default=DEFAULT_RULES)
    p_det.add_argument("--out", type=Path, required=True)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "list-scenarios":
        for sid, s in load_scenarios(args.scenarios).items():
            print(f"{sid:20s} {s['mitre']:40s} {s['name']}")
        return 0

    if args.command == "run-scenario":
        scenarios = load_scenarios(args.scenarios)
        try:
            events = run_scenario(args.scenario_id, scenarios, args.out)
        except ValueError as e:
            print(f"[!] {e}", file=sys.stderr)
            return 1
        print(f"[+] Wrote {len(events)} synthetic event(s) for scenario '{args.scenario_id}' to {args.out}")
        return 0

    if args.command == "detect":
        events = load_events(args.events)
        rules = load_rules(args.rules)
        alerts = run_detection(events, rules)
        args.out.write_text(json.dumps(alerts, indent=2, default=str))
        print(f"[+] Evaluated {len(rules)} rule(s) against {len(events)} event(s): {len(alerts)} alert(s) -> {args.out}")
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
