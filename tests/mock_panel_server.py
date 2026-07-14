"""Mock V2Board/Xboard panel for testing gray_sources registration logic.

Endpoints:
- POST /api/v1/passport/auth/register  -> {"data":{"token":"mock-token-xyz"}}
- GET  /api/v1/user/getSubscribe       -> {"data":{"subscribe_url":"http://127.0.0.1:PORT/sub"}}
- GET  /sub                            -> base64 of "vmess://... vless://... trojan://..."
"""

import base64
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8765
SUB_CONTENT = (
    "vmess://eyJ2IjoiMiIsInBzIjoibW9jay1wbGFpbiIsImFkZCI6IjEyNy4wLjAuMSIsInBvcnQiOiI0NDMifQ==\n"
    "vless://mock-uuid@127.0.0.1:443?encryption=none&security=tls\n"
    "trojan://mockpass@127.0.0.1:443?type=tcp\n"
)
SUB_B64 = base64.b64encode(SUB_CONTENT.encode()).decode()


class H(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.end_headers()
        self.wfile.write(body.encode() if isinstance(body, str) else body)

    def do_POST(self):
        if self.path.startswith("/api/v1/passport/auth/register"):
            self._send(200, '{"data":{"token":"mock-token-xyz"},"code":0}')
        else:
            self._send(404, '{"data":null,"message":"not found"}')

    def do_GET(self):
        if self.path.startswith("/api/v1/user/getSubscribe"):
            self._send(
                200,
                f'{{"data":{{"subscribe_url":"http://127.0.0.1:{PORT}/sub"}},"code":0}}',
            )
        elif self.path == "/sub":
            self._send(200, SUB_B64, ctype="text/plain")
        else:
            self._send(404, "not found")

    def log_message(self, *a, **k):
        pass


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", PORT), H).serve_forever()
