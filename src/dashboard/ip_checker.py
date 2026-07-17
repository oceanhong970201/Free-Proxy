from __future__ import annotations

import ipaddress
import json
import os
import secrets
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import uuid
from collections import Counter
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path
from statistics import median
from typing import Any, Callable
from urllib.parse import quote, urlsplit

import httpx

from aggregator.emit import UnsupportedOutbound, to_clash_dict
from aggregator.models import ProxyNode


_PROVIDERS = (
    ("edge-trace", "https://www.cloudflare.com/cdn-cgi/trace", "trace"),
    ("ip-json", "https://api64.ipify.org?format=json", "json"),
)
_PROBE_URLS = frozenset(url for _name, url, _kind in _PROVIDERS)
_TERMINAL_STATES = {"passed", "partial", "rotating", "bypass", "failed", "cancelled"}

# Provider identifiers are deliberately generic because they are persisted and
# returned to the browser.  URLs are fixed here (never accepted from a request
# or dashboard config), which keeps reputation lookups out of SSRF territory.
_REPUTATION_PROVIDERS = (
    ("network-risk", "https://api.ipquery.io/{ip}", "generic"),
    ("network-profile", "https://api.ipapi.is/?q={ip}", "generic"),
    (
        "proxy-risk",
        "https://proxycheck.io/v2/{ip}?vpn=1&asn=1&risk=1",
        "keyed",
    ),
)
_REPUTATION_HOSTS = frozenset(
    urlsplit(template).hostname for _name, template, _kind in _REPUTATION_PROVIDERS
)
_REPUTATION_RESPONSE_LIMIT = 64 * 1024
_REPUTATION_DAILY_LIMITS = {"proxy-risk": 90}
_REPUTATION_SIGNALS = frozenset(
    {
        "tor",
        "known_proxy",
        "vpn",
        "relay",
        "datacenter",
        "hosting",
        "abuse",
        "bot",
        "spam",
    }
)
_SIGNAL_RISK = {
    "tor": 95,
    "abuse": 85,
    "bot": 70,
    "spam": 65,
    "known_proxy": 55,
    "vpn": 45,
    "relay": 45,
    "datacenter": 35,
    "hosting": 30,
}
_PUBLIC_ERROR_CODES = frozenset(
    {
        "node_not_found",
        "unsupported_mode",
        "checker_runtime_unavailable",
        "invalid_proxy_config",
        "proxy_core_exited",
        "proxy_core_timeout",
        "all_ip_probes_failed",
        "all_reputation_probes_failed",
        "invalid_response",
        "cancelled",
        "timeout",
        "invalid_probe_url",
        "curl_cleanup_failed",
        "provider_timeout",
        "provider_http_error",
        "provider_invalid_response",
        "provider_response_too_large",
        "provider_unavailable",
        "provider_quota_exhausted",
        "network_error",
        "unsupported_outbound",
        "proxy_runtime_error",
        "check_failed",
    }
)


def _creation_flags() -> int:
    return int(getattr(subprocess, "CREATE_NO_WINDOW", 0))


def find_mihomo(root: Path) -> str | None:
    bundled = root / "bin" / "mihomo.exe"
    override = os.environ.get("MIHOMO_BIN", "").strip()
    candidates = [
        str(bundled),
        override,
        shutil.which("mihomo.exe") or "",
        shutil.which("mihomo") or "",
        shutil.which("clash-meta") or "",
    ]
    for value in candidates:
        if value and Path(value).is_file():
            return str(Path(value).resolve())
    return None


def find_curl() -> str | None:
    return shutil.which("curl.exe") or shutil.which("curl")


def _is_public_unicast(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> bool:
    """Reject multicast and every non-public address class."""
    return address.is_global and not address.is_multicast


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def resolve_public_endpoint(host: str, port: int) -> list[str]:
    try:
        answers = socket.getaddrinfo(
            host, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP
        )
    except OSError as exc:
        raise ValueError(f"DNS resolution failed: {exc}") from exc
    addresses = sorted({answer[4][0].split("%", 1)[0] for answer in answers})
    if not addresses:
        raise ValueError("DNS resolution returned no addresses")
    parsed = []
    for value in addresses:
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError("DNS returned an invalid address") from exc
        if not _is_public_unicast(address):
            raise ValueError("node endpoint resolved to a non-public address")
        parsed.append(address)
    parsed.sort(key=lambda address: (address.version != 4, str(address)))
    return [str(address) for address in parsed]


def _tcp_probe(host: str, port: int, timeout: float = 3.0) -> float:
    started = time.perf_counter()
    with socket.create_connection((host, port), timeout=timeout):
        return round((time.perf_counter() - started) * 1000, 1)


def _parse_provider_body(kind: str, body: str) -> dict[str, Any]:
    if len(body.encode("utf-8")) > 16_384:
        raise ValueError("IP provider response is too large")
    if kind == "trace":
        values = {}
        for line in body.splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                values[key.strip()] = value.strip()
        ip_value = values.get("ip", "")
        result = {
            "ip": ip_value,
            "country": values.get("loc"),
            "colo": values.get("colo"),
        }
    else:
        document = json.loads(body)
        if not isinstance(document, dict):
            raise ValueError("IP provider JSON is not an object")
        result = {"ip": str(document.get("ip") or "")}
    address = ipaddress.ip_address(result["ip"])
    if not _is_public_unicast(address):
        raise ValueError("IP provider returned a non-public address")
    result["ip"] = str(address)
    return result


def _safe_error_code(value: object) -> str:
    code = str(value or "").casefold()
    if code in _PUBLIC_ERROR_CODES:
        return code
    if code.startswith("curl_exit_") and code[10:].isdigit():
        return code[:32]
    return "check_failed"


def _flag(value: object) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in {0, 1}:
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().casefold()
        if normalized in {"true", "yes", "1", "detected"}:
            return True
        if normalized in {"false", "no", "0", "none", "not detected"}:
            return False
    return None


def _bounded_score(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        number = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    if number != number or number in {float("inf"), float("-inf")}:
        return None
    return int(round(max(0.0, min(100.0, number))))


def _normalize_reputation(
    provider: str,
    kind: str,
    document: object,
    exit_ip: str,
) -> dict[str, Any]:
    """Reduce provider-specific JSON to bounded, non-identifying signals."""
    if not isinstance(document, dict):
        raise ValueError("provider_invalid_response")
    current: dict[str, Any] = document
    if kind == "keyed":
        item = document.get(exit_ip)
        if not isinstance(item, dict):
            try:
                target_ip = ipaddress.ip_address(exit_ip)
            except ValueError as exc:
                raise ValueError("provider_invalid_response") from exc
            item = next(
                (
                    candidate
                    for key, candidate in document.items()
                    if isinstance(key, str)
                    and isinstance(candidate, dict)
                    and _same_ip(key, target_ip)
                ),
                None,
            )
        if not isinstance(item, dict):
            raise ValueError("provider_invalid_response")
        current = item
    elif kind != "generic":
        raise ValueError("provider_invalid_response")

    reported_ip = current.get("ip")
    if kind == "generic" and not isinstance(reported_ip, str):
        raise ValueError("provider_invalid_response")
    if reported_ip is not None and reported_ip != "":
        try:
            if ipaddress.ip_address(str(reported_ip)) != ipaddress.ip_address(exit_ip):
                raise ValueError("provider_invalid_response")
        except ValueError as exc:
            raise ValueError("provider_invalid_response") from exc

    containers = [current]
    for key in ("risk", "security", "privacy", "company", "asn"):
        item = current.get(key)
        if isinstance(item, dict):
            containers.append(item)

    aliases = {
        "tor": ("is_tor", "tor"),
        "known_proxy": ("is_proxy", "proxy"),
        "vpn": ("is_vpn", "vpn"),
        "relay": ("is_relay", "relay"),
        "datacenter": ("is_datacenter", "datacenter"),
        "hosting": ("is_hosting", "hosting"),
        "abuse": ("is_abuser", "is_abuse", "abuser", "abuse"),
        "bot": ("is_bot", "bot"),
        "spam": ("is_spam", "spam"),
    }
    signals: set[str] = set()
    for signal, keys in aliases.items():
        if any(
            _flag(container.get(key)) is True
            for container in containers
            for key in keys
        ):
            signals.add(signal)

    for container in containers:
        type_value = str(container.get("type") or "").strip().casefold()
        if "tor" in type_value:
            signals.add("tor")
        if "vpn" in type_value:
            signals.add("vpn")
        if any(token in type_value for token in ("proxy", "socks")):
            signals.add("known_proxy")
        if any(token in type_value for token in ("hosting", "datacenter")):
            signals.add("hosting")

    supplied_risks: list[int] = []
    for container in containers:
        for key in (
            "risk_score",
            "fraud_score",
            "abuse_score",
            "abuse_confidence_score",
            "risk",
            "score",
        ):
            score = _bounded_score(container.get(key))
            if score is not None:
                supplied_risks.append(score)
    inferred_risk = max((_SIGNAL_RISK[item] for item in signals), default=0)
    risk_score = max([inferred_risk, *supplied_risks])
    return {
        "provider": provider,
        "status": "ok",
        "risk_score": risk_score,
        "signals": sorted(signals),
        "cached": False,
    }


def _same_ip(
    value: str, expected: ipaddress.IPv4Address | ipaddress.IPv6Address
) -> bool:
    try:
        return ipaddress.ip_address(value) == expected
    except ValueError:
        return False


def _purity_grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def _consensus_purity(
    provider_results: list[dict[str, Any]],
) -> tuple[int, str, list[str]]:
    successful = [item for item in provider_results if item.get("status") == "ok"]
    risks = []
    for item in successful:
        risk = _bounded_score(item.get("risk_score"))
        if risk is not None:
            risks.append(risk)
    if not risks:
        raise ValueError("all_reputation_probes_failed")

    midpoint = float(median(risks))
    # The median supplies the consensus while a bounded outlier contribution
    # prevents one severe signal from disappearing entirely.
    consensus_risk = int(round(midpoint + max(0.0, max(risks) - midpoint) * 0.35))
    score = max(0, min(100, 100 - consensus_risk))

    signal_votes: Counter[str] = Counter()
    for item in successful:
        signal_votes.update(
            signal
            for signal in item.get("signals", [])
            if signal in _REPUTATION_SIGNALS
        )
    quorum = len(successful) // 2 + 1
    reasons = sorted(
        signal for signal, votes in signal_votes.items() if votes >= quorum
    )
    disagreement = _reputation_disagrees(successful)
    if disagreement:
        reasons.append("provider_disagreement")
        score = min(score, 74)
    if consensus_risk >= 50 and not any(
        item in _REPUTATION_SIGNALS for item in reasons
    ):
        reasons.append("elevated_risk")
    elif consensus_risk >= 25 and not any(
        item in _REPUTATION_SIGNALS for item in reasons
    ):
        reasons.append("moderate_risk")
    reasons = list(dict.fromkeys(reasons))
    return score, _purity_grade(score), reasons


def _reputation_disagrees(successful: list[dict[str, Any]]) -> bool:
    risks = [
        risk
        for item in successful
        if (risk := _bounded_score(item.get("risk_score"))) is not None
    ]
    return len(risks) >= 2 and max(risks) - min(risks) >= 25


def _purity_confidence(successful: list[dict[str, Any]]) -> str | None:
    count = min(3, len(successful))
    if count <= 0:
        return None
    levels = ("low", "medium", "high")
    index = count - 1
    if _reputation_disagrees(successful):
        index = max(0, index - 1)
    return levels[index]


def _stop_process(process: subprocess.Popen[str]) -> None:
    """Reap a child regardless of whether its stdin/startup path failed."""
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
    try:
        process.communicate(timeout=2)
    except (subprocess.TimeoutExpired, OSError, ValueError):
        if process.poll() is None:
            process.kill()
        try:
            process.wait(timeout=2)
        except (subprocess.TimeoutExpired, OSError):
            pass


def _mihomo_config(
    node: ProxyNode, server_ip: str, port: int, token: str
) -> dict[str, Any]:
    proxy = to_clash_dict(node)
    proxy["name"] = "PROBE_NODE"
    proxy["server"] = server_ip
    return {
        "port": 0,
        "mixed-port": 0,
        "socks-port": port,
        "redir-port": 0,
        "tproxy-port": 0,
        "allow-lan": False,
        "bind-address": "127.0.0.1",
        "authentication": [f"probe:{token}"],
        "skip-auth-prefixes": [],
        "mode": "rule",
        "log-level": "silent",
        "ipv6": True,
        "find-process-mode": "off",
        "dns": {"enable": False},
        "tun": {"enable": False},
        "sniffer": {"enable": False},
        "profile": {"store-selected": False, "store-fake-ip": False},
        "proxies": [proxy],
        "rules": ["MATCH,PROBE_NODE"],
    }


class NodeIpChecker:
    def __init__(
        self,
        *,
        root: Path,
        node_loader: Callable[[str], ProxyNode | None],
        timeout_seconds: float = 18.0,
        cache_seconds: int = 300,
        purity_timeout_seconds: float = 8.0,
        purity_cache_seconds: int = 24 * 60 * 60,
        purity_provider_concurrency: int = 2,
    ) -> None:
        self.root = root
        self.node_loader = node_loader
        self.timeout_seconds = timeout_seconds
        self.cache_seconds = cache_seconds
        self.purity_timeout_seconds = max(1.0, min(30.0, float(purity_timeout_seconds)))
        self.purity_cache_seconds = max(
            0, min(7 * 24 * 60 * 60, int(purity_cache_seconds))
        )
        provider_concurrency = max(1, min(3, int(purity_provider_concurrency)))
        self.mihomo = find_mihomo(root)
        self.curl = find_curl()
        self._cache: dict[tuple[str, str], dict[str, Any]] = {}
        self._cache_lock = threading.Lock()
        self._direct_ip: tuple[float, str | None] = (0.0, None)
        self._direct_lock = threading.Lock()
        self._reputation_cache: dict[tuple[str, str], tuple[float, dict[str, Any]]] = {}
        self._reputation_cache_lock = threading.Lock()
        self._reputation_slots = threading.BoundedSemaphore(provider_concurrency)
        self._provider_usage: dict[str, tuple[str, int]] = {}
        self._provider_usage_lock = threading.Lock()
        self._http = httpx.Client(
            follow_redirects=False,
            trust_env=False,
            headers={"Accept": "application/json", "Accept-Encoding": "identity"},
        )

    def capabilities(self) -> dict[str, Any]:
        version = None
        if self.mihomo:
            try:
                output = subprocess.check_output(
                    [self.mihomo, "-v"],
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=3,
                    creationflags=_creation_flags(),
                )
                version = output.splitlines()[0] if output.splitlines() else "detected"
            except (OSError, subprocess.SubprocessError, IndexError):
                version = "detected"
        return {
            "endpoint": True,
            "exit_ip": bool(self.mihomo and self.curl),
            "purity": bool(self.mihomo and self.curl and _REPUTATION_PROVIDERS),
            "purity_providers": [item[0] for item in _REPUTATION_PROVIDERS],
            "mihomo": version,
            "curl": bool(self.curl),
            "batch_limit": 20,
        }

    def _cached(self, node_id: str, mode: str) -> dict[str, Any] | None:
        if self.cache_seconds <= 0:
            return None
        with self._cache_lock:
            result = self._cache.get((node_id, mode))
            if not result:
                return None
            if time.time() - float(result.get("checked_at", 0)) > self.cache_seconds:
                return None
            return {**result, "cached": True}

    def _store_cache(self, node_id: str, mode: str, result: dict[str, Any]) -> None:
        if result.get("status") in {"passed", "partial", "rotating", "bypass"}:
            with self._cache_lock:
                self._cache[(node_id, mode)] = dict(result)

    def _direct_public_ip(self) -> str | None:
        with self._direct_lock:
            timestamp, cached = self._direct_ip
            if time.time() - timestamp < 300:
                return cached
            value: str | None = None
            try:
                response = self._http.get(_PROVIDERS[0][1], timeout=5)
                response.raise_for_status()
                value = _parse_provider_body("trace", response.text)["ip"]
            except Exception:
                value = None
            self._direct_ip = (time.time(), value)
            return value

    def check(
        self,
        node_id: str,
        mode: str,
        cancel_event: threading.Event | None = None,
    ) -> dict[str, Any]:
        cancel_event = cancel_event or threading.Event()
        cached = self._cached(node_id, mode)
        if cached:
            return cached
        node = self.node_loader(node_id)
        if node is None:
            return self._failure(node_id, mode, "node_not_found")
        started = time.perf_counter()
        deadline = time.monotonic() + self.timeout_seconds
        try:
            addresses = resolve_public_endpoint(node.host, node.port)
            if cancel_event.is_set():
                return self._cancelled(node_id, mode)
            tcp_latency = _tcp_probe(addresses[0], node.port)
            if mode == "endpoint":
                result = {
                    "node_id": node_id,
                    "mode": mode,
                    "status": "passed",
                    "endpoint_ips": addresses,
                    "tcp_latency_ms": tcp_latency,
                    "duration_ms": round((time.perf_counter() - started) * 1000, 1),
                    "checked_at": int(time.time()),
                    "cached": False,
                }
                self._store_cache(node_id, mode, result)
                return result
            if mode not in {"exit", "purity"}:
                return self._failure(node_id, mode, "unsupported_mode")
            if not self.mihomo or not self.curl:
                return self._failure(node_id, mode, "checker_runtime_unavailable")
            result = self._exit_check(
                node_id,
                node,
                addresses,
                tcp_latency,
                cancel_event,
                started,
                deadline,
                mode,
            )
            if mode == "purity" and result.get("status") not in {
                "failed",
                "cancelled",
            }:
                # Exit probing has its own bounded phase. Reputation providers
                # get a fresh shared deadline only after a usable exit IP was
                # established, so a slow proxy cannot consume their budget.
                purity_deadline = time.monotonic() + self.purity_timeout_seconds
                result = self._purity_check(
                    result,
                    cancel_event=cancel_event,
                    started=started,
                    deadline=purity_deadline,
                )
            self._store_cache(node_id, mode, result)
            return result
        except UnsupportedOutbound:
            return self._failure(node_id, mode, "unsupported_outbound", started)
        except subprocess.SubprocessError:
            return self._failure(node_id, mode, "proxy_runtime_error", started)
        except (OSError, ValueError):
            return self._failure(node_id, mode, "network_error", started)

    def _exit_check(
        self,
        node_id: str,
        node: ProxyNode,
        addresses: list[str],
        tcp_latency: float,
        cancel_event: threading.Event,
        started: float,
        deadline: float,
        result_mode: str,
    ) -> dict[str, Any]:
        token = secrets.token_urlsafe(24)
        port = _free_port()
        config = _mihomo_config(node, addresses[0], port, token)
        config_json = json.dumps(config, ensure_ascii=False, separators=(",", ":"))
        with tempfile.TemporaryDirectory(prefix="proxy-ip-check-") as temp_name:
            temp = Path(temp_name)
            remaining_for_syntax = deadline - time.monotonic()
            if remaining_for_syntax <= 0:
                return self._failure(node_id, result_mode, "timeout", started)
            syntax = subprocess.run(
                # mihomo v1.19.27 accepts JSON/YAML config on stdin. Keep this
                # smoke invocation minimal so it validates the same input used by
                # the runtime rather than a path-dependent temporary config.
                [self.mihomo, "-t", "-f", "-"],
                input=config_json,
                text=True,
                capture_output=True,
                timeout=max(0.25, min(6.0, remaining_for_syntax)),
                cwd=temp,
                encoding="utf-8",
                errors="replace",
                creationflags=_creation_flags(),
            )
            if syntax.returncode != 0:
                return self._failure(
                    node_id, result_mode, "invalid_proxy_config", started
                )
            process = subprocess.Popen(
                [self.mihomo, "-d", str(temp), "-f", "-"],
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                text=True,
                encoding="utf-8",
                errors="replace",
                creationflags=_creation_flags(),
            )
            try:
                assert process.stdin is not None
                process.stdin.write(config_json)
                process.stdin.close()
                while time.monotonic() < deadline:
                    if cancel_event.is_set():
                        return self._cancelled(node_id, result_mode)
                    if process.poll() is not None:
                        return self._failure(
                            node_id, result_mode, "proxy_core_exited", started
                        )
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                            break
                    except OSError:
                        time.sleep(0.08)
                else:
                    return self._failure(
                        node_id, result_mode, "proxy_core_timeout", started
                    )

                provider_results = []
                for provider, url, kind in _PROVIDERS:
                    if cancel_event.is_set():
                        return self._cancelled(node_id, result_mode)
                    remaining = max(1.0, deadline - time.monotonic())
                    probe = self._run_curl(
                        url,
                        port,
                        token,
                        min(10.0, remaining),
                        cancel_event,
                    )
                    if probe["ok"]:
                        try:
                            parsed = _parse_provider_body(kind, probe["body"])
                            provider_results.append({"provider": provider, **parsed})
                        except (ValueError, json.JSONDecodeError):
                            provider_results.append(
                                {"provider": provider, "error": "invalid_response"}
                            )
                    else:
                        provider_results.append(
                            {"provider": provider, "error": probe["error"]}
                        )
            finally:
                _stop_process(process)
        valid = [item for item in provider_results if item.get("ip")]
        if not valid:
            return self._failure(node_id, result_mode, "all_ip_probes_failed", started)
        exit_ips = sorted({str(item["ip"]) for item in valid})
        direct_ip = self._direct_public_ip()
        direct_match = bool(direct_ip and direct_ip in exit_ips)
        if direct_match:
            status = "bypass"
        elif len(valid) == len(_PROVIDERS) and len(exit_ips) == 1:
            status = "passed"
        elif len(exit_ips) > 1:
            status = "rotating"
        else:
            status = "partial"
        metadata = next((item for item in valid if item.get("country")), valid[0])
        return {
            "node_id": node_id,
            "mode": result_mode,
            "status": status,
            "endpoint_ips": addresses,
            "tcp_latency_ms": tcp_latency,
            "exit_ips": exit_ips,
            "exit_ip": exit_ips[0],
            "direct_match": direct_match,
            "country": metadata.get("country"),
            "colo": metadata.get("colo"),
            "providers": provider_results,
            "duration_ms": round((time.perf_counter() - started) * 1000, 1),
            "checked_at": int(time.time()),
            "cached": False,
        }

    def _purity_check(
        self,
        exit_result: dict[str, Any],
        *,
        cancel_event: threading.Event,
        started: float,
        deadline: float,
    ) -> dict[str, Any]:
        node_id = str(exit_result["node_id"])
        if cancel_event.is_set():
            return self._cancelled(node_id, "purity")

        # A bypass is the dashboard host's own address.  Avoid sending that
        # address to additional services and give it an unambiguous score.
        if exit_result.get("direct_match") is True:
            return {
                **exit_result,
                "mode": "purity",
                "status": "bypass",
                "purity_score": 0,
                "purity_grade": "F",
                "purity_reasons": ["direct_bypass"],
                "provider_coverage": {
                    "ok": 0,
                    "total": len(_REPUTATION_PROVIDERS),
                },
                "reputation_providers": [],
                "duration_ms": round((time.perf_counter() - started) * 1000, 1),
            }

        exit_ip = str(exit_result.get("exit_ip") or "")
        try:
            address = ipaddress.ip_address(exit_ip)
        except ValueError:
            return self._failure(
                node_id, "purity", "all_reputation_probes_failed", started
            )
        if not _is_public_unicast(address):
            return self._failure(
                node_id, "purity", "all_reputation_probes_failed", started
            )
        exit_ip = str(address)

        provider_results: list[dict[str, Any]] = []
        for provider, template, kind in _REPUTATION_PROVIDERS:
            if cancel_event.is_set():
                return self._cancelled(node_id, "purity")
            cached = self._cached_reputation(exit_ip, provider)
            if cached is not None:
                provider_results.append(cached)
                continue
            result = self._fetch_reputation(
                provider,
                template,
                kind,
                exit_ip,
                cancel_event,
                deadline,
            )
            if result.get("error") == "cancelled":
                return self._cancelled(node_id, "purity")
            provider_results.append(result)
            if result.get("status") == "ok":
                self._store_reputation(exit_ip, provider, result)

        successful = [item for item in provider_results if item.get("status") == "ok"]
        confidence = _purity_confidence(successful)
        coverage = {
            "ok": len(successful),
            "total": len(_REPUTATION_PROVIDERS),
        }
        if not successful:
            return {
                **exit_result,
                "mode": "purity",
                "status": "failed",
                "error": "all_reputation_probes_failed",
                "provider_coverage": coverage,
                "reputation_providers": provider_results,
                "duration_ms": round((time.perf_counter() - started) * 1000, 1),
            }

        try:
            score, grade, reasons = _consensus_purity(provider_results)
        except ValueError:
            return {
                **exit_result,
                "mode": "purity",
                "status": "failed",
                "error": "all_reputation_probes_failed",
                "provider_coverage": coverage,
                "reputation_providers": provider_results,
                "duration_ms": round((time.perf_counter() - started) * 1000, 1),
            }

        base_status = str(exit_result.get("status") or "partial")
        if base_status == "rotating":
            score = min(score, 59)
            grade = _purity_grade(score)
            reasons.append("rotating_exit")
        if len(successful) < len(_REPUTATION_PROVIDERS):
            reasons.append("limited_provider_coverage")
            status = "partial"
        elif base_status in {"partial", "rotating"}:
            status = base_status
        else:
            status = "passed"
        if (
            score < 40
            and "elevated_risk" not in reasons
            and not any(item in _REPUTATION_SIGNALS for item in reasons)
        ):
            reasons.append("elevated_risk")
        return {
            **exit_result,
            "mode": "purity",
            "status": status,
            "purity_score": score,
            "purity_grade": grade,
            "purity_confidence": confidence,
            "purity_reasons": list(dict.fromkeys(reasons)),
            "provider_coverage": coverage,
            "reputation_providers": provider_results,
            "duration_ms": round((time.perf_counter() - started) * 1000, 1),
            "cached": False,
        }

    def _cached_reputation(self, exit_ip: str, provider: str) -> dict[str, Any] | None:
        if self.purity_cache_seconds <= 0:
            return None
        with self._reputation_cache_lock:
            cached = self._reputation_cache.get((exit_ip, provider))
            if cached is None:
                return None
            stored_at, result = cached
            if time.time() - stored_at > self.purity_cache_seconds:
                self._reputation_cache.pop((exit_ip, provider), None)
                return None
            return {
                **result,
                "signals": list(result.get("signals", [])),
                "cached": True,
            }

    def _store_reputation(
        self, exit_ip: str, provider: str, result: dict[str, Any]
    ) -> None:
        if self.purity_cache_seconds <= 0:
            return
        clean = {
            "provider": provider,
            "status": "ok",
            "risk_score": int(result.get("risk_score", 0)),
            "signals": [
                item
                for item in result.get("signals", [])
                if item in _REPUTATION_SIGNALS
            ],
            "cached": False,
        }
        with self._reputation_cache_lock:
            self._reputation_cache[(exit_ip, provider)] = (time.time(), clean)

    def _reserve_provider_request(self, provider: str) -> bool:
        """Apply a conservative in-process UTC-day budget to limited adapters."""
        limit = _REPUTATION_DAILY_LIMITS.get(provider)
        if limit is None:
            return True
        today = time.strftime("%Y-%m-%d", time.gmtime())
        with self._provider_usage_lock:
            stored_day, count = self._provider_usage.get(provider, (today, 0))
            if stored_day != today:
                count = 0
            if count >= limit:
                self._provider_usage[provider] = (today, count)
                return False
            self._provider_usage[provider] = (today, count + 1)
        return True

    def _fetch_reputation(
        self,
        provider: str,
        template: str,
        kind: str,
        exit_ip: str,
        cancel_event: threading.Event,
        deadline: float,
    ) -> dict[str, Any]:
        acquired = False
        while time.monotonic() < deadline:
            if cancel_event.is_set():
                return {
                    "provider": provider,
                    "status": "error",
                    "error": "cancelled",
                }
            if self._reputation_slots.acquire(timeout=0.1):
                acquired = True
                break
        if not acquired:
            return {
                "provider": provider,
                "status": "error",
                "error": "provider_timeout",
            }
        try:
            encoded_ip = quote(exit_ip, safe="")
            url = template.format(ip=encoded_ip)
            parsed = urlsplit(url)
            if (
                parsed.scheme != "https"
                or parsed.hostname not in _REPUTATION_HOSTS
                or parsed.username is not None
                or parsed.password is not None
                or parsed.port not in {None, 443}
                or parsed.fragment
            ):
                return {
                    "provider": provider,
                    "status": "error",
                    "error": "provider_unavailable",
                }
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise httpx.TimeoutException("deadline exhausted")
            if not self._reserve_provider_request(provider):
                return {
                    "provider": provider,
                    "status": "error",
                    "error": "provider_quota_exhausted",
                }
            timeout = httpx.Timeout(max(0.25, min(5.0, remaining)))
            with self._http.stream("GET", url, timeout=timeout) as response:
                if not 200 <= response.status_code < 300:
                    return {
                        "provider": provider,
                        "status": "error",
                        "error": "provider_http_error",
                    }
                body = bytearray()
                for chunk in response.iter_bytes(chunk_size=8192):
                    if cancel_event.is_set():
                        return {
                            "provider": provider,
                            "status": "error",
                            "error": "cancelled",
                        }
                    if time.monotonic() >= deadline:
                        return {
                            "provider": provider,
                            "status": "error",
                            "error": "provider_timeout",
                        }
                    body.extend(chunk)
                    if len(body) > _REPUTATION_RESPONSE_LIMIT:
                        return {
                            "provider": provider,
                            "status": "error",
                            "error": "provider_response_too_large",
                        }
            document = json.loads(body.decode("utf-8"))
            return _normalize_reputation(provider, kind, document, exit_ip)
        except httpx.TimeoutException:
            return {
                "provider": provider,
                "status": "error",
                "error": "provider_timeout",
            }
        except httpx.HTTPError:
            return {
                "provider": provider,
                "status": "error",
                "error": "provider_unavailable",
            }
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            return {
                "provider": provider,
                "status": "error",
                "error": "provider_invalid_response",
            }
        finally:
            self._reputation_slots.release()

    def _run_curl(
        self,
        url: str,
        port: int,
        token: str,
        timeout: float,
        cancel_event: threading.Event,
    ) -> dict[str, Any]:
        if url not in _PROBE_URLS or not url.startswith("https://"):
            return {"ok": False, "error": "invalid_probe_url"}
        command = [
            self.curl,
            "--silent",
            "--show-error",
            "--fail-with-body",
            "--proxy",
            f"socks5h://127.0.0.1:{port}",
            "--proxy-user",
            f"probe:{token}",
            "--connect-timeout",
            "5",
            "--max-time",
            str(max(1, int(timeout))),
            "--max-filesize",
            "16384",
            "--proto",
            "=https",
            "--header",
            "Accept-Encoding: identity",
            "--",
            url,
        ]
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            creationflags=_creation_flags(),
        )
        deadline = time.monotonic() + timeout + 1
        while process.poll() is None:
            if cancel_event.is_set() or time.monotonic() >= deadline:
                _stop_process(process)
                return {
                    "ok": False,
                    "error": "cancelled" if cancel_event.is_set() else "timeout",
                }
            time.sleep(0.08)
        try:
            stdout, _stderr = process.communicate(timeout=2)
        except (OSError, subprocess.TimeoutExpired):
            _stop_process(process)
            return {"ok": False, "error": "curl_cleanup_failed"}
        if process.returncode != 0:
            return {"ok": False, "error": f"curl_exit_{process.returncode}"}
        return {"ok": True, "body": stdout}

    @staticmethod
    def _failure(
        node_id: str,
        mode: str,
        error: str,
        started: float | None = None,
    ) -> dict[str, Any]:
        return {
            "node_id": node_id,
            "mode": mode,
            "status": "failed",
            "error": _safe_error_code(error),
            "duration_ms": round((time.perf_counter() - started) * 1000, 1)
            if started is not None
            else 0,
            "checked_at": int(time.time()),
            "cached": False,
        }

    @staticmethod
    def _cancelled(node_id: str, mode: str) -> dict[str, Any]:
        return {
            "node_id": node_id,
            "mode": mode,
            "status": "cancelled",
            "checked_at": int(time.time()),
            "cached": False,
        }

    def close(self) -> None:
        self._http.close()


class IpCheckJobManager:
    def __init__(
        self,
        checker: NodeIpChecker,
        *,
        max_workers: int,
        persist: Callable[[dict[str, Any]], None],
    ) -> None:
        self.checker = checker
        self.persist = persist
        self.executor = ThreadPoolExecutor(
            max_workers=max_workers, thread_name_prefix="ip-check"
        )
        self.lock = threading.RLock()
        self.jobs: dict[str, dict[str, Any]] = {}

    def create(self, node_ids: list[str], mode: str) -> dict[str, Any]:
        unique_ids = list(dict.fromkeys(node_ids))
        if not unique_ids or len(unique_ids) > 20:
            raise ValueError("node_ids must contain between 1 and 20 unique values")
        if mode not in {"endpoint", "exit", "purity"}:
            raise ValueError("mode must be endpoint, exit, or purity")
        job_id = uuid.uuid4().hex
        cancel_event = threading.Event()
        job = {
            "id": job_id,
            "mode": mode,
            "status": "queued",
            "created_at": int(time.time()),
            "completed_at": None,
            "cancel_event": cancel_event,
            "items": {
                node_id: {"node_id": node_id, "status": "queued"}
                for node_id in unique_ids
            },
            "futures": {},
        }
        with self.lock:
            self.jobs[job_id] = job
            self._trim_jobs()
        for node_id in unique_ids:
            future = self.executor.submit(self._run_item, job_id, node_id)
            with self.lock:
                current = self.jobs.get(job_id)
                if current is not None:
                    current["futures"][node_id] = future
        return self.snapshot(job_id) or {}

    def _run_item(self, job_id: str, node_id: str) -> None:
        with self.lock:
            job = self.jobs.get(job_id)
            if not job:
                return
            if job["cancel_event"].is_set():
                job["items"][node_id] = {"node_id": node_id, "status": "cancelled"}
                self._finish_if_complete(job)
                return
            job["status"] = "running"
            job["items"][node_id] = {"node_id": node_id, "status": "running"}
            mode = job["mode"]
            cancel_event = job["cancel_event"]
        try:
            result = self.checker.check(node_id, mode, cancel_event)
        except Exception as exc:
            # Unexpected worker errors must complete the item, otherwise a job
            # can remain "running" forever and never be trimmed.
            result = NodeIpChecker._failure(node_id, mode, type(exc).__name__)
        with self.lock:
            job = self.jobs.get(job_id)
            if not job:
                return
            job["items"][node_id] = result
            self._finish_if_complete(job)
        try:
            self.persist(result)
        except Exception:
            # Persistence cannot be allowed to take down a worker thread.
            pass

    def _finish_if_complete(self, job: dict[str, Any]) -> None:
        states = [item["status"] for item in job["items"].values()]
        if all(state in _TERMINAL_STATES for state in states):
            job["status"] = (
                "cancelled"
                if all(state == "cancelled" for state in states)
                else "completed"
            )
            job["completed_at"] = int(time.time())

    def cancel(self, job_id: str) -> dict[str, Any] | None:
        with self.lock:
            job = self.jobs.get(job_id)
            if not job:
                return None
            job["cancel_event"].set()
            for node_id, item in job["items"].items():
                if item["status"] == "queued":
                    job["items"][node_id] = {"node_id": node_id, "status": "cancelled"}
                    future = job["futures"].get(node_id)
                    if isinstance(future, Future):
                        future.cancel()
            self._finish_if_complete(job)
        return self.snapshot(job_id)

    def snapshot(self, job_id: str) -> dict[str, Any] | None:
        with self.lock:
            job = self.jobs.get(job_id)
            if not job:
                return None
            items = list(job["items"].values())
            counts = Counter(item["status"] for item in items)
            return {
                "id": job["id"],
                "mode": job["mode"],
                "status": job["status"],
                "created_at": job["created_at"],
                "completed_at": job["completed_at"],
                "total": len(items),
                "completed": sum(
                    count
                    for state, count in counts.items()
                    if state in _TERMINAL_STATES
                ),
                "counts": dict(counts),
                "items": items,
            }

    def _trim_jobs(self) -> None:
        if len(self.jobs) <= 50:
            return
        completed = sorted(
            (
                (job.get("completed_at") or 0, job_id)
                for job_id, job in self.jobs.items()
                if job.get("completed_at")
            )
        )
        for _timestamp, job_id in completed[: len(self.jobs) - 50]:
            self.jobs.pop(job_id, None)

    def close(self) -> None:
        with self.lock:
            for job in self.jobs.values():
                job["cancel_event"].set()
                for node_id, item in job["items"].items():
                    if item["status"] == "queued":
                        job["items"][node_id] = {
                            "node_id": node_id,
                            "status": "cancelled",
                        }
                self._finish_if_complete(job)
        self.executor.shutdown(wait=False, cancel_futures=True)
        close = getattr(self.checker, "close", None)
        if callable(close):
            close()
