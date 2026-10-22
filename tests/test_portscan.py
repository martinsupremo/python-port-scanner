"""Unit tests for portscan.py. Run: python3 -m unittest discover -s tests -v"""
import json
import os
import socket
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import portscan  # noqa: E402


def make_test_server(banner: bytes) -> tuple[int, threading.Thread, socket.socket]:
    """Start a throwaway TCP server on 127.0.0.1 that speaks `banner`."""
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def serve() -> None:
        conn, _ = srv.accept()
        with conn:
            if banner:
                conn.sendall(banner)
            else:  # silent server: answer only after client sends something
                conn.recv(1024)
                conn.sendall(b"HTTP/1.0 200 OK\r\nServer: TestSrv/1.0\r\n\r\n")

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return port, thread, srv


class TestParsePorts(unittest.TestCase):
    def test_single(self):
        self.assertEqual(portscan.parse_ports("22"), [22])

    def test_list_and_range(self):
        self.assertEqual(portscan.parse_ports("80-82,443"), [80, 81, 82, 443])

    def test_dedup_sorted(self):
        self.assertEqual(portscan.parse_ports("443,80,80"), [80, 443])

    def test_rejects_bad_range(self):
        with self.assertRaises(ValueError):
            portscan.parse_ports("99999")
        with self.assertRaises(ValueError):
            portscan.parse_ports("10-5")


class TestScope(unittest.TestCase):
    def test_private_allows_loopback_and_private(self):
        self.assertTrue(portscan.is_scan_allowed("127.0.0.1", "private"))
        self.assertTrue(portscan.is_scan_allowed("192.168.1.5", "private"))
        self.assertTrue(portscan.is_scan_allowed("10.0.0.9", "private"))
        self.assertTrue(portscan.is_scan_allowed("172.16.5.5", "private"))

    def test_private_refuses_public(self):
        self.assertFalse(portscan.is_scan_allowed("8.8.8.8", "private"))

    def test_private_refuses_non_rfc1918_special_ranges(self):
        # ip.is_private matches these; the explicit allow-list must not.
        self.assertFalse(portscan.is_scan_allowed("169.254.10.20", "private"))  # link-local
        self.assertFalse(portscan.is_scan_allowed("192.0.2.1", "private"))     # TEST-NET-1
        self.assertFalse(portscan.is_scan_allowed("198.18.0.1", "private"))    # benchmarking
        self.assertFalse(portscan.is_scan_allowed("240.0.0.1", "private"))     # reserved

    def test_own_scope_allows_public(self):
        self.assertTrue(portscan.is_scan_allowed("8.8.8.8", "own"))


class TestScanPort(unittest.TestCase):
    def test_banner_port(self):
        port, thread, srv = make_test_server(b"SSH-2.0-OpenSSH_9.6 TestSrv\r\n")
        result = portscan.scan_port("127.0.0.1", port, 2.0)
        self.assertIsNotNone(result)
        self.assertIn("OpenSSH", result["banner"])
        srv.close()

    def test_silent_server_gets_http_probe(self):
        port, thread, srv = make_test_server(b"")
        result = portscan.scan_port("127.0.0.1", port, 2.0)
        self.assertIsNotNone(result)
        self.assertIn("HTTP/1.0 200", result["banner"])
        srv.close()

    def test_closed_port_returns_none(self):
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        closed = sock.getsockname()[1]
        sock.close()
        self.assertIsNone(portscan.scan_port("127.0.0.1", closed, 0.5))


class TestOutputs(unittest.TestCase):
    def test_csv_and_json_roundtrip(self):
        results = [portscan.SERVICE_HINTS and {
            "target": "127.0.0.1", "port": 22, "state": "open",
            "service": "ssh", "banner": "SSH-2.0-test", "rtt_ms": 1.0,
        }]
        with tempfile.TemporaryDirectory() as tmp:
            csv_path = os.path.join(tmp, "out.csv")
            json_path = os.path.join(tmp, "out.json")
            portscan.write_csv(csv_path, results)
            portscan.write_json(json_path, results, {"target": "127.0.0.1"})
            with open(json_path) as fh:
                data = json.load(fh)
            self.assertEqual(data["results"][0]["port"], 22)
            with open(csv_path) as fh:
                self.assertIn("22,open,ssh", fh.read().replace(",", ",", 1).replace("127.0.0.1,", ""))


class TestExpandTargets(unittest.TestCase):
    def test_cidr_expansion(self):
        self.assertEqual(
            portscan.expand_targets("127.0.0.0/30"),
            ["127.0.0.0", "127.0.0.1", "127.0.0.2", "127.0.0.3"],
        )

    def test_single_slash32(self):
        self.assertEqual(portscan.expand_targets("192.168.1.5/32"), ["192.168.1.5"])

    def test_comma_separated_mix(self):
        self.assertEqual(
            portscan.expand_targets("127.0.0.1, 192.168.1.5,127.0.0.1"),
            ["127.0.0.1", "192.168.1.5"],
        )

    def test_cidr_and_host_mix(self):
        self.assertEqual(
            portscan.expand_targets("127.0.0.0/31,127.0.0.3"),
            ["127.0.0.0", "127.0.0.1", "127.0.0.3"],
        )

    def test_hostname_resolves(self):
        self.assertEqual(portscan.expand_targets("localhost"), ["127.0.0.1"])

    def test_rejects_unresolvable(self):
        # A malformed label fails locally even behind wildcard DNS, which
        # would otherwise "resolve" any well-formed made-up hostname.
        with self.assertRaises(ValueError):
            portscan.expand_targets("no_such_host!.invalid")

    def test_rejects_bad_subnet(self):
        with self.assertRaises(ValueError):
            portscan.expand_targets("127.0.0.0/99")

    def test_rejects_too_large_subnet(self):
        with self.assertRaises(ValueError):
            portscan.expand_targets("10.0.0.0/8")  # 16M addresses > MAX_TARGETS


class TestTargetSetGuard(unittest.TestCase):
    def test_guard_rejects_set_with_any_public(self):
        bad = portscan.disallowed_targets(["127.0.0.1", "8.8.8.8"], "private")
        self.assertEqual(bad, ["8.8.8.8"])

    def test_guard_accepts_all_private(self):
        self.assertEqual(
            portscan.disallowed_targets(["127.0.0.1", "192.168.1.9"], "private"), []
        )

    def test_guard_own_allows_set(self):
        self.assertEqual(
            portscan.disallowed_targets(["127.0.0.1", "8.8.8.8"], "own"), []
        )

    def test_main_refuses_whole_run_on_one_public(self):
        rc = portscan.main(
            ["127.0.0.1,8.8.8.8", "--ports", "80", "--output", "/tmp/nope"]
        )
        self.assertEqual(rc, 2)

    def test_main_cidr_set_refuses_public(self):
        rc = portscan.main(
            ["8.8.8.0/30", "--ports", "80", "--output", "/tmp/nope"]
        )
        self.assertEqual(rc, 2)


class TestFingerprint(unittest.TestCase):
    def test_ssh_banner(self):
        self.assertEqual(
            portscan.fingerprint_service("SSH-2.0-OpenSSH_9.6 TestSrv", 2222), "ssh"
        )

    def test_http_banner(self):
        self.assertEqual(
            portscan.fingerprint_service("HTTP/1.1 200 OK", 8080), "http"
        )

    def test_smtp_banner(self):
        self.assertEqual(
            portscan.fingerprint_service("220 mail.example.com ESMTP Postfix", 25),
            "smtp",
        )

    def test_ftp_banner(self):
        self.assertEqual(
            portscan.fingerprint_service("220 (vsFTPd 3.0.3)", 21), "ftp"
        )

    def test_mysql_banner(self):
        self.assertEqual(
            portscan.fingerprint_service("8.0.33 MySQL Community Server", 3306),
            "mysql",
        )

    def test_rdp_heuristic(self):
        self.assertEqual(
            portscan.fingerprint_service("\x03\x00\x00\x13\x0e", 3389), "rdp"
        )

    def test_falls_back_to_port_hint(self):
        self.assertEqual(portscan.fingerprint_service("", 5900), "vnc")

    def test_empty_and_unknown(self):
        self.assertEqual(portscan.fingerprint_service("", 49999), "")


class TestHtmlOutput(unittest.TestCase):
    def test_html_exists_and_contains_target(self):
        results = [{
            "target": "127.0.0.1", "port": 8080, "state": "open",
            "service": "http", "banner": "HTTP/1.0 200 OK", "rtt_ms": 1.2,
        }]
        meta = {"target": "127.0.0.0/30", "targets": ["127.0.0.0", "127.0.0.1"],
                "ports_scanned": 2, "scope": "private",
                "started_utc": "2026-10-20T00:00:00+00:00", "elapsed_s": 0.3}
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "report.html")
            portscan.write_html(path, results, meta)
            self.assertTrue(os.path.exists(path))
            with open(path) as fh:
                content = fh.read()
            self.assertIn("127.0.0.1", content)
            self.assertIn("PRIVATE SCOPE", content)
            self.assertIn("<style>", content)
            # Self-contained: no external assets are referenced.
            self.assertNotIn('src="http', content)
            self.assertNotIn('href="http', content)

    def test_html_handles_no_open_ports(self):
        meta = {"target": "127.0.0.1", "targets": ["127.0.0.1"],
                "ports_scanned": 1, "scope": "private",
                "started_utc": "2026-10-20T00:00:00+00:00", "elapsed_s": 0.1}
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "empty.html")
            portscan.write_html(path, [], meta)
            with open(path) as fh:
                content = fh.read()
            self.assertIn("127.0.0.1", content)
            self.assertIn("No open ports", content)


if __name__ == "__main__":
    unittest.main()
