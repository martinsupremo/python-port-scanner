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
    def test_lab_allows_loopback_and_private(self):
        self.assertTrue(portscan.is_scan_allowed("127.0.0.1", "lab"))
        self.assertTrue(portscan.is_scan_allowed("192.168.1.5", "lab"))
        self.assertTrue(portscan.is_scan_allowed("10.0.0.9", "lab"))

    def test_lab_refuses_public(self):
        self.assertFalse(portscan.is_scan_allowed("8.8.8.8", "lab"))

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


if __name__ == "__main__":
    unittest.main()
