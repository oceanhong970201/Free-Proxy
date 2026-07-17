from __future__ import annotations

import ipaddress
import json
import mimetypes
import re
import socket
import threading
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qs, urlsplit

from .ip_checker import IpCheckJobManager, NodeIpChecker
from .service import DashboardService


_NODE_ID_RE = re.compile(r"^[0-9a-f]{64}$")
_JOB_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_MAX_BODY_BYTES = 16 * 1024
_STATIC_FILES = {
    "/": "index.html",
    "/index.html": "index.html",
    "/app.css": "app.css",
    "/app.js": "app.js",
}
_CSP = (
    "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; "
    "form-action 'none'; object-src 'none'; script-src 'self'; "
    "style-src 'self'; img-src 'self' data:; connect-src 'self'"
)


def _is_loopback(value: str | None) -> bool:
    if not value:
        return False
    normalized = value.rstrip(".").casefold()
    if normalized == "localhost":
        return True
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


def _host_parts(value: str) -> tuple[str | None, int | None]:
    if (
        not value
        or value != value.strip()
        or any(character.isspace() for character in value)
        or any(character in value for character in "/\\?#@,")
    ):
        return None, None
    try:
        parsed = urlsplit(f"http://{value}")
        if (
            parsed.username is not None
            or parsed.password is not None
            or parsed.path
            or parsed.query
            or parsed.fragment
        ):
            return None, None
        return parsed.hostname, parsed.port
    except ValueError:
        return None, None


class DashboardHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        server_address: tuple[str, int],
        handler: type[BaseHTTPRequestHandler],
        *,
        root: Path,
    ) -> None:
        self.root = root.resolve()
        self.static_root = Path(__file__).resolve().parent / "static"
        self.dashboard_service = DashboardService(self.root)
        cfg = self.dashboard_service.config
        self.node_checker = NodeIpChecker(
            root=self.root,
            node_loader=self.dashboard_service.node_for_check,
            timeout_seconds=cfg.checker_timeout_seconds,
            cache_seconds=cfg.checker_cache_seconds,
            purity_timeout_seconds=cfg.purity_timeout_seconds,
            purity_cache_seconds=cfg.purity_cache_seconds,
            purity_provider_concurrency=cfg.purity_provider_concurrency,
        )

        def persist(result: dict[str, Any]) -> None:
            callback = getattr(self.dashboard_service, "persist_ip_result", None)
            if callable(callback):
                callback(result)

        self.job_manager = IpCheckJobManager(
            self.node_checker,
            max_workers=cfg.checker_concurrency,
            persist=persist,
        )
        try:
            super().__init__(server_address, handler)
        except BaseException:
            self.job_manager.close()
            raise

    def server_close(self) -> None:
        self.job_manager.close()
        super().server_close()


class DashboardRequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "ProxyDashboard/1"
    sys_version = ""

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(15)

    def handle(self) -> None:
        try:
            super().handle()
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            # Browsers routinely cancel keep-alive requests during refresh or
            # navigation. They are not dashboard failures and need no traceback.
            self.close_connection = True

    @property
    def app(self) -> DashboardHTTPServer:
        return self.server  # type: ignore[return-value]

    def log_message(self, _format: str, *_args: Any) -> None:
        # Request paths contain opaque IDs. Keep the local server quiet and avoid
        # accidentally introducing sensitive logging if new routes are added.
        return

    def _security_headers(self, *, api: bool) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header(
            "Permissions-Policy",
            "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
        )
        self.send_header("Content-Security-Policy", _CSP)
        self.send_header("Cache-Control", "no-store" if api else "no-cache")
        if api:
            self.send_header("Pragma", "no-cache")

    def _write(
        self,
        status: int,
        body: bytes,
        content_type: str,
        *,
        api: bool,
        include_body: bool = True,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if self.close_connection:
            self.send_header("Connection", "close")
        self._security_headers(api=api)
        self.end_headers()
        if include_body and self.command != "HEAD":
            self.wfile.write(body)

    def _json(
        self,
        status: int,
        payload: dict[str, Any] | list[Any],
        *,
        include_body: bool = True,
    ) -> None:
        try:
            body = json.dumps(
                payload,
                ensure_ascii=False,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
        except (TypeError, ValueError):
            status = HTTPStatus.INTERNAL_SERVER_ERROR
            body = b'{"error":"serialization_error"}'
        self._write(
            int(status),
            body,
            "application/json; charset=utf-8",
            api=True,
            include_body=include_body,
        )

    def _error(self, status: int, code: str, detail: str | None = None) -> None:
        payload: dict[str, Any] = {"error": code}
        if detail:
            payload["detail"] = detail[:240]
        self._json(status, payload)

    def _trusted_host(self) -> bool:
        values = self.headers.get_all("Host", failobj=[])
        if len(values) != 1:
            return False
        host, port = _host_parts(values[0])
        bound_port = int(self.server.server_address[1])
        return _is_loopback(host) and (port is None or port == bound_port)

    def _trusted_origin(self) -> bool:
        origin = self.headers.get("Origin")
        if not origin:
            return True
        try:
            parsed = urlsplit(origin)
            port = parsed.port or (80 if parsed.scheme == "http" else None)
        except ValueError:
            return False
        return (
            parsed.scheme == "http"
            and parsed.username is None
            and parsed.password is None
            and _is_loopback(parsed.hostname)
            and port == int(self.server.server_address[1])
            and parsed.path in {"", "/"}
            and not parsed.query
            and not parsed.fragment
        )

    def _preflight(self, *, mutating: bool = False) -> bool:
        if not self._trusted_host():
            self._error(HTTPStatus.MISDIRECTED_REQUEST, "untrusted_host")
            return False
        if mutating and not self._trusted_origin():
            self._error(HTTPStatus.FORBIDDEN, "untrusted_origin")
            return False
        return True

    def _read_json(self) -> dict[str, Any] | None:
        if self.headers.get("Transfer-Encoding"):
            self.close_connection = True
            self._error(HTTPStatus.BAD_REQUEST, "unsupported_transfer_encoding")
            return None
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip()
        if content_type.casefold() != "application/json":
            self._error(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "json_required")
            return None
        lengths = self.headers.get_all("Content-Length", failobj=[])
        if len(lengths) != 1:
            self.close_connection = True
            self._error(HTTPStatus.BAD_REQUEST, "ambiguous_content_length")
            return None
        try:
            length = int(lengths[0])
        except ValueError:
            self.close_connection = True
            self._error(HTTPStatus.LENGTH_REQUIRED, "content_length_required")
            return None
        if length < 0 or length > _MAX_BODY_BYTES:
            self.close_connection = True
            self._error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "body_too_large")
            return None
        try:
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise EOFError("incomplete request body")
            value = json.loads(raw.decode("utf-8")) if raw else {}
        except (EOFError, TimeoutError, UnicodeDecodeError, json.JSONDecodeError):
            self.close_connection = True
            self._error(HTTPStatus.BAD_REQUEST, "invalid_json")
            return None
        if not isinstance(value, dict):
            self._error(HTTPStatus.BAD_REQUEST, "json_object_required")
            return None
        return value

    def do_HEAD(self) -> None:  # noqa: N802
        if not self._preflight():
            return
        path = urlsplit(self.path).path
        if path.startswith("/api/"):
            self._error(HTTPStatus.METHOD_NOT_ALLOWED, "method_not_allowed")
            return
        self._serve_static(path, include_body=False)

    def do_GET(self) -> None:  # noqa: N802
        if not self._preflight():
            return
        parsed = urlsplit(self.path)
        if parsed.path.startswith("/api/"):
            self._handle_api_get(parsed.path, parse_qs(parsed.query, keep_blank_values=True))
            return
        if parsed.query:
            self._error(HTTPStatus.NOT_FOUND, "not_found")
            return
        self._serve_static(parsed.path)

    def do_POST(self) -> None:  # noqa: N802
        if not self._preflight(mutating=True):
            return
        parsed = urlsplit(self.path)
        if parsed.query:
            self._error(HTTPStatus.BAD_REQUEST, "query_not_allowed")
            return
        payload = self._read_json()
        if payload is None:
            return
        if parsed.path == "/api/ip-checks":
            try:
                self._create_job(payload)
            except Exception:
                self._error(HTTPStatus.INTERNAL_SERVER_ERROR, "internal_error")
            return
        match = re.fullmatch(r"/api/ip-checks/([0-9a-f]{32})/cancel", parsed.path)
        if match:
            if payload:
                self._error(HTTPStatus.BAD_REQUEST, "unexpected_fields")
                return
            snapshot = self.app.job_manager.cancel(match.group(1))
            if snapshot is None:
                self._error(HTTPStatus.NOT_FOUND, "job_not_found")
            else:
                self._json(HTTPStatus.OK, snapshot)
            return
        self._error(HTTPStatus.NOT_FOUND, "not_found")

    def _handle_api_get(self, path: str, query: dict[str, list[str]]) -> None:
        try:
            if path == "/api/status":
                allowed = {"force"}
                if set(query) - allowed:
                    raise ValueError("unsupported status query")
                force = self._one(query, "force", "false") in {"1", "true", "yes"}
                if force and (
                    not self._trusted_origin()
                    or self.headers.get("X-Dashboard-Action") != "refresh"
                ):
                    self._error(HTTPStatus.FORBIDDEN, "untrusted_origin")
                    return
                payload = self.app.dashboard_service.status(force_remote=force)
                payload["ip_checker"] = {
                    **self.app.node_checker.capabilities(),
                    "concurrency": self.app.dashboard_service.config.checker_concurrency,
                }
                self._json(HTTPStatus.OK, payload)
                return
            if path == "/api/sources":
                if query:
                    raise ValueError("sources does not accept query parameters")
                items = self.app.dashboard_service.sources()
                self._json(HTTPStatus.OK, {"items": items, "total": len(items)})
                return
            if path == "/api/nodes":
                allowed = {
                    "query",
                    "status",
                    "proto",
                    "source",
                    "published",
                    "offset",
                    "limit",
                }
                if set(query) - allowed:
                    raise ValueError("unsupported nodes query")
                status = self._one(query, "status", "all")
                published = self._one(query, "published", "all")
                if status not in {"all", "alive", "dead", "unverified"}:
                    raise ValueError("invalid status filter")
                if published not in {"all", "yes", "no"}:
                    raise ValueError("invalid published filter")
                payload = self.app.dashboard_service.nodes(
                    query=self._one(query, "query", "")[:160],
                    status=status,
                    proto=self._one(query, "proto", "all")[:40],
                    source=self._one(query, "source", "all")[:160],
                    published=published,
                    offset=self._bounded_int(query, "offset", 0, 0, 1_000_000),
                    limit=self._bounded_int(query, "limit", 50, 1, 200),
                )
                self._json(HTTPStatus.OK, payload)
                return
            match = re.fullmatch(r"/api/ip-checks/([0-9a-f]{32})", path)
            if match:
                if query:
                    raise ValueError("job lookup does not accept query parameters")
                snapshot = self.app.job_manager.snapshot(match.group(1))
                if snapshot is None:
                    self._error(HTTPStatus.NOT_FOUND, "job_not_found")
                else:
                    self._json(HTTPStatus.OK, snapshot)
                return
            self._error(HTTPStatus.NOT_FOUND, "not_found")
        except ValueError as exc:
            self._error(HTTPStatus.BAD_REQUEST, "invalid_query", str(exc))
        except Exception:
            self._error(HTTPStatus.INTERNAL_SERVER_ERROR, "internal_error")

    @staticmethod
    def _one(query: dict[str, list[str]], key: str, default: str) -> str:
        values = query.get(key)
        if not values:
            return default
        if len(values) != 1:
            raise ValueError(f"{key} must be provided once")
        return values[0]

    @classmethod
    def _bounded_int(
        cls,
        query: dict[str, list[str]],
        key: str,
        default: int,
        minimum: int,
        maximum: int,
    ) -> int:
        raw = cls._one(query, key, str(default))
        try:
            value = int(raw)
        except ValueError as exc:
            raise ValueError(f"{key} must be an integer") from exc
        if not minimum <= value <= maximum:
            raise ValueError(f"{key} is outside the accepted range")
        return value

    def _create_job(self, payload: dict[str, Any]) -> None:
        if set(payload) - {"node_ids", "mode"}:
            self._error(HTTPStatus.BAD_REQUEST, "unexpected_fields")
            return
        node_ids = payload.get("node_ids")
        mode = payload.get("mode", "endpoint")
        if (
            not isinstance(node_ids, list)
            or not 1 <= len(node_ids) <= 20
            or any(not isinstance(value, str) or not _NODE_ID_RE.fullmatch(value) for value in node_ids)
        ):
            self._error(HTTPStatus.BAD_REQUEST, "invalid_node_ids")
            return
        if len(set(node_ids)) != len(node_ids):
            self._error(HTTPStatus.BAD_REQUEST, "duplicate_node_ids")
            return
        if mode not in {"endpoint", "exit", "purity"}:
            self._error(HTTPStatus.BAD_REQUEST, "invalid_mode")
            return
        missing = [
            node_id
            for node_id in node_ids
            if self.app.dashboard_service.node_for_check(node_id) is None
        ]
        if missing:
            self._error(HTTPStatus.BAD_REQUEST, "unknown_node_ids")
            return
        capability = "purity" if mode == "purity" else "exit_ip"
        if mode in {"exit", "purity"} and not self.app.node_checker.capabilities().get(
            capability
        ):
            self._error(HTTPStatus.SERVICE_UNAVAILABLE, "checker_runtime_unavailable")
            return
        try:
            snapshot = self.app.job_manager.create(node_ids, str(mode))
        except ValueError as exc:
            self._error(HTTPStatus.BAD_REQUEST, "invalid_job", str(exc))
            return
        self._json(HTTPStatus.ACCEPTED, snapshot)

    def _serve_static(self, path: str, *, include_body: bool = True) -> None:
        name = _STATIC_FILES.get(path)
        if not name:
            self._error(HTTPStatus.NOT_FOUND, "not_found")
            return
        file_path = self.app.static_root / name
        try:
            body = file_path.read_bytes()
        except OSError:
            self._error(HTTPStatus.NOT_FOUND, "asset_missing")
            return
        content_type = mimetypes.guess_type(name)[0] or "application/octet-stream"
        if content_type.startswith("text/") or content_type in {
            "application/javascript",
            "application/json",
        }:
            content_type += "; charset=utf-8"
        self._write(
            HTTPStatus.OK,
            body,
            content_type,
            api=False,
            include_body=include_body,
        )


def create_server(
    root: Path,
    host: str = "127.0.0.1",
    port: int = 8765,
) -> DashboardHTTPServer:
    if not _is_loopback(host):
        raise ValueError("dashboard host must be a loopback address")
    if isinstance(port, bool) or not 0 <= int(port) <= 65535:
        raise ValueError("dashboard port must be between 0 and 65535")
    root = root.resolve()
    if not root.is_dir():
        raise ValueError("dashboard root does not exist")

    if ":" in host:
        class IPv6DashboardHTTPServer(DashboardHTTPServer):
            address_family = socket.AF_INET6

        server_type: Callable[..., DashboardHTTPServer] = IPv6DashboardHTTPServer
    else:
        server_type = DashboardHTTPServer
    return server_type((host, int(port)), DashboardRequestHandler, root=root)


def serve(
    root: Path,
    host: str = "127.0.0.1",
    port: int = 8765,
    open_browser: bool = False,
) -> None:
    server = create_server(root, host=host, port=port)
    actual_port = int(server.server_address[1])
    display_host = f"[{host}]" if ":" in host else host
    url = f"http://{display_host}:{actual_port}/"
    print(f"Dashboard listening on {url}", flush=True)
    if open_browser:
        threading.Timer(0.25, webbrowser.open, args=(url,)).start()
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    serve(Path(__file__).resolve().parents[2])
