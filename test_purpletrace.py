"""Tests for PurpleTrace. Run with: pytest test_purpletrace.py -v"""

import json
from datetime import datetime, timezone
from pathlib import Path

import purpletrace as pt


# --- scenario loading / generation -----------------------------------------

def test_load_scenarios_has_all_four():
    scenarios = pt.load_scenarios()
    assert set(scenarios) == {"T1087-enum", "T1110-bruteforce", "T1059-susproc", "T1003-credaccess"}


def test_all_generated_events_are_marked_simulated():
    scenarios = pt.load_scenarios()
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    for sid in scenarios:
        events = pt.generate_events(sid, start)
        assert events, f"{sid} produced no events"
        for e in events:
            assert e["simulated"] is True
            assert e["scenario_id"] == sid


def test_generate_events_unknown_scenario_raises():
    import pytest
    with pytest.raises(ValueError):
        pt.generate_events("does-not-exist", datetime.now(timezone.utc))


def test_run_scenario_writes_jsonl(tmp_path: Path):
    scenarios = pt.load_scenarios()
    out = tmp_path / "events.jsonl"
    events = pt.run_scenario("T1110-bruteforce", scenarios, out)
    lines = out.read_text().splitlines()
    assert len(lines) == len(events) == 12
    assert json.loads(lines[0])["event_type"] == "auth_failure"


def test_run_scenario_appends_not_overwrites(tmp_path: Path):
    scenarios = pt.load_scenarios()
    out = tmp_path / "events.jsonl"
    pt.run_scenario("T1087-enum", scenarios, out)
    pt.run_scenario("T1059-susproc", scenarios, out)
    lines = out.read_text().splitlines()
    assert len(lines) == 6 + 3


# --- detection rules ---------------------------------------------------------

def test_load_rules_has_four_rules():
    rules = pt.load_rules()
    assert len(rules) == 4
    assert {r["id"] for r in rules} == {
        "DET-T1087-enum", "DET-T1110-bruteforce", "DET-T1059-susproc", "DET-T1003-credaccess",
    }


def test_T1110_bruteforce_triggers_its_rule():
    scenarios, rules = pt.load_scenarios(), pt.load_rules()
    events = pt.generate_events("T1110-bruteforce", datetime(2026, 1, 1, tzinfo=timezone.utc))
    alerts = pt.run_detection(events, rules)
    assert any(a["rule_id"] == "DET-T1110-bruteforce" for a in alerts)


def test_T1087_enum_triggers_its_rule():
    scenarios, rules = pt.load_scenarios(), pt.load_rules()
    events = pt.generate_events("T1087-enum", datetime(2026, 1, 1, tzinfo=timezone.utc))
    alerts = pt.run_detection(events, rules)
    matched = [a for a in alerts if a["rule_id"] == "DET-T1087-enum"]
    assert len(matched) == 1
    assert matched[0]["matched_count"] == 6


def test_T1059_susproc_triggers_one_alert_per_event():
    rules = pt.load_rules()
    events = pt.generate_events("T1059-susproc", datetime(2026, 1, 1, tzinfo=timezone.utc))
    alerts = pt.run_detection(events, rules)
    matched = [a for a in alerts if a["rule_id"] == "DET-T1059-susproc"]
    assert len(matched) == 3  # match-kind rule: one alert per matching event


def test_T1003_credaccess_triggers_for_both_paths():
    rules = pt.load_rules()
    events = pt.generate_events("T1003-credaccess", datetime(2026, 1, 1, tzinfo=timezone.utc))
    alerts = pt.run_detection(events, rules)
    matched = [a for a in alerts if a["rule_id"] == "DET-T1003-credaccess"]
    assert len(matched) == 2  # both /etc/shadow and the SAM-style path match contains_any


def test_benign_unrelated_event_triggers_nothing():
    rules = pt.load_rules()
    benign = [{
        "simulated": True, "scenario_id": "none", "host": "h", "ts": "2026-01-01T00:00:00Z",
        "event_type": "process_creation", "user": "jdoe",
        "parent_process": "explorer.exe", "process": "notepad.exe", "command_line": "notepad.exe report.txt",
    }]
    assert pt.run_detection(benign, rules) == []


def test_detect_cli_end_to_end(tmp_path: Path):
    scenarios = pt.load_scenarios()
    events_path = tmp_path / "events.jsonl"
    pt.run_scenario("T1110-bruteforce", scenarios, events_path)

    out_path = tmp_path / "alerts.json"
    rc = pt.main(["detect", "--events", str(events_path), "--out", str(out_path)])
    assert rc == 0
    alerts = json.loads(out_path.read_text())
    assert any(a["rule_id"] == "DET-T1110-bruteforce" for a in alerts)
