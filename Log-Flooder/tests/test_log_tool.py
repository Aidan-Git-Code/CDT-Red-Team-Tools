#!/usr/bin/env python3
"""
tests/test_log_tool.py
Unit tests for log_tool.py — importable functions only (no root, no network).

Run from the repo root:
    python3 -m pytest tests/test_log_tool.py -v
  or without pytest:
    python3 tests/test_log_tool.py
"""

import json
import os
import socket
import sys
import tempfile
import threading
import pathlib
import unittest

# Allow importing log_tool from the parent directory.
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))
import log_tool


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_temp_log(lines: list[str]) -> str:
    """Write lines to a temp file and return its path."""
    tf = tempfile.NamedTemporaryFile(
        mode="w", suffix=".log", delete=False
    )
    tf.write("\n".join(lines) + "\n")
    tf.close()
    return tf.name


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestReadLogs(unittest.TestCase):

    def test_reads_existing_file(self):
        path = _write_temp_log([
            "Jan 1 00:00:01 host sshd[1234]: Failed password for root",
            "Jan 1 00:00:02 host sshd[1234]: Accepted password for alice",
        ])
        entries = log_tool.read_logs([path])
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0][0], path)
        os.unlink(path)

    def test_skips_missing_file(self):
        entries = log_tool.read_logs(["/nonexistent/path.log"])
        self.assertEqual(entries, [])

    def test_returns_stripped_lines(self):
        path = _write_temp_log(["  hello world  "])
        entries = log_tool.read_logs([path])
        self.assertEqual(entries[0][1], "hello world")
        os.unlink(path)


class TestExtractInfo(unittest.TestCase):

    def setUp(self):
        self.lines = [
            "Failed password for invalid user admin from 192.168.1.10 port 22",
            "Accepted publickey for alice from 10.0.0.5 port 54321",
            "sudo: bob : TTY=pts/0 ; USER=root ; COMMAND=/bin/bash",
            "Routine heartbeat — nothing to see here",
        ]
        self.path = _write_temp_log(self.lines)

    def tearDown(self):
        os.unlink(self.path)

    def test_ip_extraction(self):
        findings = log_tool.extract_info([self.path], [])
        ips = [ip for f in findings for ip in f["ips"]]
        self.assertIn("192.168.1.10", ips)
        self.assertIn("10.0.0.5", ips)

    def test_keyword_matching(self):
        findings = log_tool.extract_info([self.path], ["sudo"])
        kw_hits  = [f for f in findings if "sudo" in f["keywords"]]
        self.assertGreater(len(kw_hits), 0)

    def test_auth_failure_flag(self):
        findings = log_tool.extract_info([self.path], [])
        flagged  = [f for f in findings if "auth_failure_or_error" in f["flags"]]
        self.assertGreater(len(flagged), 0)

    def test_uninteresting_line_excluded(self):
        findings = log_tool.extract_info([self.path], [])
        lines    = [f["line"] for f in findings]
        # The heartbeat line has no IPs, users, or flags — should not appear.
        self.assertNotIn("Routine heartbeat — nothing to see here", lines)

    def test_hash_present(self):
        findings = log_tool.extract_info([self.path], [])
        for f in findings:
            self.assertIn("hash", f)
            self.assertEqual(len(f["hash"]), 64)  # SHA-256 hex digest

    def test_service_field_is_none_or_two_elements(self):
        """
        Regression: service field must be None or a 2-element list [name, pid].
        A partial regex match must never produce a 1-element list that causes
        an IndexError when the display loop accesses svc[1].
        """
        findings = log_tool.extract_info([self.path], [])
        for f in findings:
            svc = f.get("service")
            if svc is not None:
                self.assertEqual(len(svc), 2,
                    f"service field must have exactly 2 elements, got: {svc}")


class TestSaveAndLoad(unittest.TestCase):

    def test_roundtrip(self):
        findings = [
            {
                "source": "/var/log/auth.log",
                "line": "test line",
                "timestamp": "2025-01-01T00:00:00Z",
                "ips": ["1.2.3.4"],
                "users": ["alice"],
                "ports": ["22"],
                "keywords": ["failed"],
                "flags": ["auth_failure_or_error"],
                "hash": "abc123",
            }
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = pathlib.Path(tmpdir)
            outfile = log_tool.save_findings(findings, storage)
            self.assertTrue(outfile.exists())

            loaded = log_tool.load_findings(storage)
            self.assertEqual(len(loaded), 1)
            self.assertEqual(loaded[0]["line"], "test line")

    def test_deduplication(self):
        """Saving the same finding twice should yield one entry after load."""
        finding = {
            "source": "/var/log/syslog",
            "line": "duplicate line",
            "timestamp": "2025-01-01T00:00:00Z",
            "ips": [], "users": [], "ports": [],
            "keywords": [], "flags": [],
            "hash": "dedup_hash_abc",
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = pathlib.Path(tmpdir)
            log_tool.save_findings([finding], storage)
            log_tool.save_findings([finding], storage)
            loaded = log_tool.load_findings(storage)
            self.assertEqual(len(loaded), 1)


class TestSummarise(unittest.TestCase):

    def test_top_ips(self):
        findings = [
            {"ips": ["1.1.1.1"], "users": [], "flags": [], "source": "/a"},
            {"ips": ["1.1.1.1"], "users": [], "flags": [], "source": "/a"},
            {"ips": ["2.2.2.2"], "users": [], "flags": [], "source": "/b"},
        ]
        summary = log_tool.summarise_findings(findings)
        self.assertEqual(summary["top_ips"][0], ("1.1.1.1", 2))

    def test_empty(self):
        summary = log_tool.summarise_findings([])
        self.assertEqual(summary["total_findings"], 0)


# ---------------------------------------------------------------------------
# Forwarder / CollectionServer round-trip
# ---------------------------------------------------------------------------

class TestForwarderServerRoundtrip(unittest.TestCase):
    """
    Spins up a real CollectionServer on a random localhost port, sends
    findings through LogForwarder, and verifies the server wrote them to disk.

    This is the class of test that would have caught the UnicodeDecodeError
    bug — the server was trying to decode the 4-byte length prefix as UTF-32
    because the old newline-split approach left it in the payload.
    """

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.storage = pathlib.Path(self.tmpdir.name)

        # Bind to a random free port on loopback.
        self.server = log_tool.CollectionServer("127.0.0.1", 0, self.storage)

        # Start a real TCP server socket to learn the assigned port.
        self._srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv_sock.bind(("127.0.0.1", 0))
        self.port = self._srv_sock.getsockname()[1]
        self._srv_sock.listen(5)
        self._srv_sock.settimeout(2.0)

        # Patch the server to use our pre-bound socket.
        self._server_thread = threading.Thread(
            target=self._accept_loop, daemon=True
        )
        self._server_thread.start()

    def _accept_loop(self):
        """Accept one connection and hand it to CollectionServer._handle_client."""
        try:
            conn, addr = self._srv_sock.accept()
            self.server._handle_client(conn, addr)
        except socket.timeout:
            pass

    def tearDown(self):
        self._srv_sock.close()
        self.tmpdir.cleanup()

    def test_findings_survive_roundtrip(self):
        """Findings sent by LogForwarder must arrive intact at the server."""
        findings = [
            {
                "source": "/var/log/auth.log",
                "line":   "Failed password for root from 192.168.1.1 port 22",
                "timestamp": "2025-01-01T00:00:00+00:00",
                "ips":    ["192.168.1.1"],
                "users":  ["root"],
                "ports":  ["22"],
                "service": ["sshd", "1234"],
                "keywords": ["failed"],
                "flags":  ["auth_failure_or_error"],
                "hash":   "abc123",
            }
        ]

        forwarder = log_tool.LogForwarder("127.0.0.1", self.port, timeout=3)
        sent, failed = forwarder.send(findings)

        self.assertEqual(sent, 1)
        self.assertEqual(failed, 0)

        # Give the server thread time to write.
        self._server_thread.join(timeout=3)

        loaded = log_tool.load_findings(self.storage)
        self.assertEqual(len(loaded), 1)
        self.assertEqual(loaded[0]["line"], findings[0]["line"])
        self.assertEqual(loaded[0]["ips"],  ["192.168.1.1"])

    def test_no_unicode_error_on_binary_length_prefix(self):
        """
        Regression: the 4-byte big-endian length prefix must never be fed to
        json.loads() directly.  The old newline-split approach caused Python to
        try decoding it as UTF-32-BE, raising UnicodeDecodeError.
        """
        findings = [{"source": "/test", "line": "test", "timestamp": "t",
                     "ips": [], "users": [], "ports": [], "service": None,
                     "keywords": [], "flags": [], "hash": "x"}]

        forwarder = log_tool.LogForwarder("127.0.0.1", self.port, timeout=3)
        # If the bug is present this raises UnicodeDecodeError inside the
        # server thread and the entry is never saved — so we check it lands.
        try:
            forwarder.send(findings)
        except Exception as e:
            self.fail(f"send() raised unexpectedly: {e}")

        self._server_thread.join(timeout=3)
        loaded = log_tool.load_findings(self.storage)
        self.assertGreater(len(loaded), 0, "Server failed to store the entry — possible framing bug")


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    loader = unittest.TestLoader()
    suite  = loader.loadTestsFromModule(sys.modules[__name__])
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
