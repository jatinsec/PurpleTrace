# PurpleTrace

A **lab-based attack-simulation and defensive detection-validation toolkit**. It generates
benign, clearly-labelled synthetic log events that mimic the shape of real telemetry for a few
common MITRE ATT&CK techniques, then runs sample detection logic against them — so you can
validate "would my logging/detection rule actually have caught this?" without running anything
dangerous.

**PurpleTrace never executes a real technique.** `run-scenario` only writes JSON lines to a local
file; it never opens a socket to a remote host, never dumps a real credential store, never runs a
real brute-force against anything. Every generated event is tagged `"simulated": true`.

## Scenarios

| ID | MITRE technique | What it simulates |
|---|---|---|
| `T1087-enum` | T1087.001 — Account Discovery | A burst of `net user`/`net group` process-creation events |
| `T1110-bruteforce` | T1110 — Brute Force | 12 auth-failure events for one account from one IP in ~1 minute |
| `T1059-susproc` | T1059 — Command and Scripting Interpreter | PowerShell spawned as a child of Word/Excel/Outlook with an encoded (harmless) command line |
| `T1003-credaccess` | T1003 — OS Credential Dumping | A file-access event against a known credential-store path (`/etc/shadow`, SAM-style path) |

Full descriptions: `scenarios.yaml`. Sample detection logic for each: `detection_rules.yaml`.

## Installation

```bash
git clone https://github.com/jatinpatel-hacker33/PurpleTrace.git
cd PurpleTrace
pip install -r requirements.txt       # pyyaml, needed to run the tool itself
pip install -r requirements-dev.txt   # pytest, only needed for tests
```

## Usage

```bash
# 1. List available scenarios
python3 purpletrace.py list-scenarios

# 2. Generate synthetic events for one scenario
python3 purpletrace.py run-scenario T1110-bruteforce --out lab/events.jsonl

# 3. Run the sample detection rules against those events
python3 purpletrace.py detect --events lab/events.jsonl --out lab/alerts.json
cat lab/alerts.json
```

Example `alerts.json` entry for the brute-force scenario:

```json
{
  "rule_id": "DET-T1110-bruteforce",
  "rule_name": "Authentication brute-force burst",
  "mitre": "T1110",
  "group_key": {"user": "svc_backup", "source_ip": "203.0.113.77"},
  "matched_count": 12,
  "window_minutes": 5
}
```

(`203.0.113.0/24` is IANA's reserved TEST-NET-3 range — used here deliberately so no real IP
appears in any sample output.)

## How the detection logic works

`detection_rules.yaml` defines simple, transparent rules of two kinds:
- **`match`** — alert on any single event matching a set of field conditions (e.g. "child process
  is a script interpreter AND parent is an Office app").
- **`threshold`** — alert when events matching a condition, grouped by a key (e.g. `user` +
  `source_ip`), reach a minimum count inside a time window.

This is intentionally a small, readable rule engine (`purpletrace.py::evaluate_rule`), not a
general-purpose SIEM query language — see Limitations.

## How a defender would investigate each simulated event

- **T1087 (enumeration):** pivot on the `host`+`user` in the alert; check what ran immediately
  before/after `net.exe` on that host, and whether the account normally runs enumeration commands.
- **T1110 (brute force):** check whether `source_ip` is expected for that user (VPN range, known
  workstation); check whether any of the attempts in the window eventually succeeded.
- **T1059 (suspicious process):** decode the `-Enc` base64 command line (here it decodes to a
  harmless string, `Write-Output PurpleTrace-Simulated`) and check the parent document's origin
  (email attachment? macro-enabled?).
- **T1003 (credential-store access):** check the accessing process's integrity/signature and
  whether it had a legitimate reason to touch that path; this alone is not proof of compromise.

## Tests

```bash
pytest test_purpletrace.py -v
```

12 tests covering: all four scenarios produce correctly-labelled synthetic events, each scenario's
matching detection rule fires, an unrelated benign event triggers nothing, and the CLI runs
end-to-end from scenario generation through detection output.

## Limitations (honest)

- The detection engine is deliberately simple: `threshold` rules use one sliding window check
  (first-to-last timestamp span vs. a minute threshold), not a true multi-window sliding
  aggregation — fine for these four demo scenarios, not a production correlation engine.
- Only four scenarios are implemented; this is a starting skeleton, not a MITRE ATT&CK coverage
  matrix.
- Events are synthetic from the start — PurpleTrace does not ingest or replay real EDR/SIEM log
  data, so it validates rule *logic*, not your actual production pipeline's parsing of real
  vendor log formats.
- No real process is spawned, no real file is read, no real network connection is made, by design.

## Scope & safety

Run this only against your own lab environment or a detection-engineering sandbox you control.
Even though every event is synthetic, treat generated log files as lab artifacts — don't ingest
them into a shared production SIEM where they could be mistaken for a real incident without the
`"simulated": true` field being checked first.
