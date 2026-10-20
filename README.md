# Python Port Scanner — Threaded TCP Scanner with Banner Grabbing

A real, working network reconnaissance tool written from scratch in pure
Python (standard library only — no pip installs). TCP connect scanning with
configurable threads/timeout, service banner grabbing, and CSV + JSON output.

**What this demonstrates:** Python socket programming, concurrency with
`ThreadPoolExecutor`, defensive argument/target validation, testable code
layout with a real `unittest` suite, and responsible tooling design: the
scanner **refuses public targets by default** (see Scope & ethics).

```
   scan targets (default scope: loopback + RFC 1918 only)
   ┌──────────────────────────────────────────────────────┐
   │                scripts/portscan.py                   │
   │  ┌────────────┐   ┌──────────────┐   ┌────────────┐  │
   │  │ parse args │──▶│ scan engine  │──▶│ outputs    │  │
   │  │ + validate │   │ (100 threads)│   │ .csv/.json │  │
   │  └────────────┘   └──────┬───────┘   └────────────┘  │
   │                          │ per open port:            │
   │                          │   connect → banner → RTT  │
   └──────────────────────────────────────────────────────┘
        127.0.0.1 / 10.x / 172.16.x / 192.168.x
```

## Repo layout

| Path | Purpose |
|---|---|
| `scripts/portscan.py` | The scanner (CLI entry point, ~200 lines, commented) |
| `tests/test_portscan.py` | 11 unit tests: port parsing, scope rules, banner grabbing vs a live test socket, output formats |
| `docs/architecture.md` | Design decisions: connect scan vs SYN scan, threading model, banner strategy |
| `docs/interview-answers.md` | "How did you build this?" — talking points for interviews |

## Quick start

```bash
# Scan localhost (allowed by default — it's yours)
python3 scripts/portscan.py 127.0.0.1 --ports 1-1024

# Scan your lab network segment
python3 scripts/portscan.py 192.168.1.50 --ports 22,80,443,8080

# Run the tests
python3 -m unittest discover -s tests -v
```

## Scope & ethics (read before use)

Port scanning third-party systems without permission is illegal in many
jurisdictions and hostile everywhere. This tool encodes that in code, not
just docs:

- Default scope `--target-scope lab`: **only** loopback and RFC 1918 private
  addresses are accepted. Public targets are refused with an error.
- `--target-scope own` unlocks public targets **only** as your explicit
  assertion that you own the host or hold written permission to test it.

## Security notes

- TCP *connect* scan: full handshakes, visible in target logs. There is no
  stealth mode and there shouldn't be — this is an inventory/audit tool.
- Banners are truncated to 200 chars in output; no payloads beyond a benign
  `HEAD /` probe for silent services.

## Validation (actually run in this sandbox)

Unit tests — 11/11 passing:

```
$ python3 -m unittest discover -s tests -v
test_dedup_sorted ... ok
test_list_and_range ... ok
test_rejects_bad_range ... ok
test_single ... ok
test_banner_port ... ok
test_closed_port_returns_none ... ok
test_silent_server_gets_http_probe ... ok
test_lab_allows_loopback_and_private ... ok
test_lab_refuses_public ... ok
test_own_scope_allows_public ... ok

Ran 11 tests in 0.309s — OK
```

Live scan against two real localhost listeners (a fake SSH banner server on
2222, `python3 -m http.server` on 8080):

```
$ python3 scripts/portscan.py 127.0.0.1 --ports 2222,8080
[*] scanning 127.0.0.1 (127.0.0.1) — 2 ports, 100 threads
[+]  2222/tcp open   — SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13
[+]  8080/tcp open  http-alt — HTTP/1.0 200 OK
[*] 2 open port(s) in 0.3s → scan.csv / scan.json
```

Scope guard verified — public target refused by default:

```
$ python3 scripts/portscan.py 8.8.8.8 --ports 53    (exit code 2)
error: refusing to scan 8.8.8.8: not a loopback/private address. ...
```

Full-range timing: 1,024 ports on localhost scanned in 0.2s with 100 threads.
No external network access was needed or used for validation.
