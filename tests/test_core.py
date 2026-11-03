import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from reconkit import cli, core


class H(BaseHTTPRequestHandler):
    server_version = "TestSrv/1.0"
    sys_version = ""
    def do_GET(self):
        self.send_response(200)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(b"<html><title> Lab  Page </title></html>")

    def log_message(self, *a):
        pass


class CoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = HTTPServer(("127.0.0.1", 0), H)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def test_parse_ports(self):
        self.assertEqual(core.parse_ports("80,22,8000-8002,80"), [22, 80, 8000, 8001, 8002])
        with self.assertRaises(ValueError):
            core.parse_ports("70000")

    def test_scope_blocks_public(self):
        self.assertTrue(core.is_private("127.0.0.1"))
        self.assertFalse(core.is_private("8.8.8.8"))
        with self.assertRaises(core.ScopeError):
            core.check_scope("8.8.8.8", authorized=False)
        self.assertEqual(core.check_scope("8.8.8.8", authorized=True), "8.8.8.8")

    def test_port_scan_finds_open_and_skips_closed(self):
        res = core.scan_ports("127.0.0.1", [self.port, 1], timeout=0.5)
        self.assertEqual([r.port for r in res], [self.port])

    def test_http_probe(self):
        r = core.probe_http(f"http://127.0.0.1:{self.port}")
        self.assertEqual(r.status, 200)
        self.assertEqual(r.title, "Lab Page")
        self.assertEqual(r.server, "TestSrv/1.0")
        self.assertNotIn("X-Content-Type-Options", r.missing_headers)
        self.assertIn("Content-Security-Policy", r.missing_headers)

    def test_http_probe_error(self):
        self.assertTrue(core.probe_http("http://127.0.0.1:1", timeout=1).error)

    def test_subdomain_bruteforce_localhost(self):
        hits = core.bruteforce_subdomains("localhost", ["www", "zzzz-nope"])
        self.assertTrue(all(n.endswith(".localhost") for n, _ in hits))

    def test_cli_end_to_end_json(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "r.json"
            rc = cli.run(["127.0.0.1", "-p", str(self.port), "-o", str(out)])
            self.assertEqual(rc, 0)
            data = json.loads(out.read_text())
            self.assertEqual(data["ports"][0]["port"], self.port)
            md = core.to_markdown(core.Report("x", "1.2.3.4"))
            self.assertIn("No open ports", md)

    def test_cli_refuses_public_without_flag(self):
        self.assertEqual(cli.run(["8.8.8.8", "-p", "53"]), 2)


if __name__ == "__main__":
    unittest.main()
