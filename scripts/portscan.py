#!/usr/bin/env python3
"""portscan.py — a clean, threaded TCP port scanner with banner grabbing.

Standard library only. Built as a portfolio/lab tool.

Scope & ethics
--------------
By default this tool only scans targets you own: loopback addresses and
RFC 1918 private ranges (10/8, 172.16/12, 192.168/16). Scanning any other
address requires the explicit flag ``--target-scope own`` — your assertion
that you own the target or have written permission to test it. Never scan
systems you do not own or lack permission for.
"""
from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

# Well-known service guesses for open ports (banner, when present, is better).
SERVICE_HINTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "smb",
    3306: "mysql", 3389: "rdp", 5432: "postgresql", 5900: "vnc",
    6379: "redis", 8080: "http-alt",
}

PRIVATE_ONLY_MSG = (
    "refusing to scan {target}: not a loopback/private address. "
    "Only scan systems you own or have written permission to test. "
    "If this is your own host, pass --target-scope own."
)


def is_scan_allowed(target: str, scope: str) -> bool:
    """Return True if the target is in scope.

    scope='lab' (default): loopback + RFC1918 private addresses only.
    scope='own': user asserts ownership/written permission; any address.
    """
    if scope == "own":
        return True
    try:
        ip = ipaddress.ip_address(target)
    except ValueError:
        return False  # unresolvable / malformed hosts handled by caller
    return ip.is_loopback or ip.is_private


def parse_ports(spec: str) -> list[int]:
    """Parse '80', '80,443', '1-1024', '22,80-82' into a sorted unique list."""
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_s, end_s = part.split("-", 1)
            start, end = int(start_s), int(end_s)
            if not (1 <= start <= end <= 65535):
                raise ValueError(f"bad range: {part!r}")
            ports.update(range(start, end + 1))
        else:
            port = int(part)
            if not 1 <= port <= 65535:
                raise ValueError(f"bad port: {part!r}")
            ports.add(port)
    if not ports:
        raise ValueError("no ports given")
    return sorted(ports)


def grab_banner(sock: socket.socket, timeout: float) -> str:
    """Read a service banner; send an HTTP probe if the peer waits silently."""
    # Short initial wait: chatty services (SSH, FTP) speak up immediately.
    sock.settimeout(min(timeout, 0.3))
    try:
        data = sock.recv(1024)
    except (socket.timeout, OSError):
        data = b""
    if not data:
        # Quiet services (HTTP) speak only after we do.
        sock.settimeout(timeout)
        try:
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            data = sock.recv(1024)
        except (socket.timeout, OSError):
            data = b""
    return data.decode("utf-8", "replace").strip().splitlines()[0] if data else ""


def scan_port(target: str, port: int, timeout: float) -> dict | None:
    """Return a result dict for an OPEN port, else None."""
    started = time.monotonic()
    try:
        with socket.create_connection((target, port), timeout=timeout) as sock:
            banner = grab_banner(sock, timeout)
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None
    rtt_ms = round((time.monotonic() - started) * 1000, 1)
    return {
        "target": target,
        "port": port,
        "state": "open",
        "service": SERVICE_HINTS.get(port, ""),
        "banner": banner[:200],
        "rtt_ms": rtt_ms,
    }


def scan(target: str, ports: list[int], timeout: float, threads: int) -> list[dict]:
    """Scan ports concurrently; return sorted results for open ports."""
    results: list[dict] = []
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(scan_port, target, p, timeout): p for p in ports}
        for future in as_completed(futures):
            result = future.result()
            if result:
                results.append(result)
    return sorted(results, key=lambda r: r["port"])


def write_csv(path: str, results: list[dict]) -> None:
    with open(path, "w", newline="") as fh:
        writer = csv.DictWriter(
            fh, fieldnames=["target", "port", "state", "service", "banner", "rtt_ms"]
        )
        writer.writeheader()
        writer.writerows(results)


def write_json(path: str, results: list[dict], meta: dict) -> None:
    with open(path, "w") as fh:
        json.dump({"meta": meta, "results": results}, fh, indent=2)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Threaded TCP port scanner with banner grabbing (lab tool)."
    )
    parser.add_argument("target", help="IP address or hostname to scan")
    parser.add_argument(
        "--ports", default="1-1024",
        help="ports to scan: '80', '80,443', '1-1024', '22,80-82' (default 1-1024)",
    )
    parser.add_argument("--timeout", type=float, default=1.0, help="seconds per port")
    parser.add_argument("--threads", type=int, default=100, help="concurrent workers")
    parser.add_argument(
        "--target-scope", choices=["lab", "own"], default="lab",
        help="lab (default): only loopback/private targets. own: you assert you "
             "own the target or have written permission to test it.",
    )
    parser.add_argument(
        "--output", default="scan",
        help="output file prefix (writes <prefix>.csv and <prefix>.json)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        target_ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print(f"error: cannot resolve {args.target!r}", file=sys.stderr)
        return 2
    if not is_scan_allowed(target_ip, args.target_scope):
        print("error: " + PRIVATE_ONLY_MSG.format(target=args.target), file=sys.stderr)
        return 2
    try:
        ports = parse_ports(args.ports)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    meta = {
        "target": args.target,
        "resolved": target_ip,
        "ports_scanned": len(ports),
        "scope": args.target_scope,
        "started_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    print(f"[*] scanning {args.target} ({target_ip}) — {len(ports)} ports, "
          f"{args.threads} threads", flush=True)
    started = time.monotonic()
    results = scan(target_ip, ports, args.timeout, args.threads)
    elapsed = time.monotonic() - started
    meta["elapsed_s"] = round(elapsed, 1)

    write_csv(args.output + ".csv", results)
    write_json(args.output + ".json", results, meta)

    for r in results:
        banner = f" — {r['banner']}" if r["banner"] else ""
        print(f"[+] {r['port']:>5}/tcp open  {r['service']}{banner}")
    print(f"[*] {len(results)} open port(s) in {elapsed:.1f}s "
          f"→ {args.output}.csv / {args.output}.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
