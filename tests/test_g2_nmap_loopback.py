from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from src.aggregator import scanner


class _ProbeHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        body = b"fixture-ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        return


class _FixtureServer(ThreadingHTTPServer):
    def handle_error(self, *_args):
        # Port/service probes commonly close before the HTTP handler replies.
        return


@pytest.mark.skipif(not scanner._nmap_available(), reason="nmap is not installed")
def test_nmap_fallback_discovers_and_fingerprints_loopback(
    monkeypatch: pytest.MonkeyPatch, tmp_path
):
    discovery_xml = tmp_path / "discovery.xml"
    fingerprint_xml = tmp_path / "fingerprint.xml"
    monkeypatch.setattr(scanner, "NMAP_DISCOVERY_OUT", discovery_xml)
    monkeypatch.setattr(scanner, "NMAP_OUT", fingerprint_xml)

    server = _FixtureServer(("127.0.0.1", 0), _ProbeHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_port
        open_ports = scanner.run_nmap_discovery(["127.0.0.1"], [port], 100)
        assert any(
            item.host == "127.0.0.1" and item.port == port for item in open_ports
        )

        services = scanner.run_nmap(open_ports)
        service = next(
            item for item in services if item.host == "127.0.0.1" and item.port == port
        )
        assert service.service in {"http", "http-proxy", "unknown"}
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
