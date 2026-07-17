from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import math
import os
import re
import sqlite3
import subprocess
import threading
import time
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from statistics import median
from typing import Any
from urllib.parse import urlparse
from xml.etree import ElementTree

import httpx
import yaml

from aggregator.models import ProxyNode
from aggregator.parser import parse_uri


@dataclass(frozen=True)
class DashboardConfig:
    worker_url: str = ""
    pipeline_status_url: str = ""
    refresh_seconds: int = 30
    remote_timeout_seconds: float = 8.0
    pipeline_status_timeout_seconds: float = 5.0
    pipeline_status_cache_seconds: int = 60
    pipeline_status_stale_seconds: int = 60 * 60
    checker_timeout_seconds: float = 18.0
    checker_concurrency: int = 4
    checker_cache_seconds: int = 300
    purity_timeout_seconds: float = 8.0
    purity_cache_seconds: int = 24 * 60 * 60
    purity_provider_concurrency: int = 2


def _clamped_float(
    value: object,
    default: float,
    minimum: float,
    maximum: float,
) -> float:
    if isinstance(value, bool):
        return default
    try:
        number = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default
    if not math.isfinite(number):
        return default
    return max(minimum, min(maximum, number))


def _clamped_int(
    value: object,
    default: int,
    minimum: int,
    maximum: int,
) -> int:
    if isinstance(value, bool):
        return default
    try:
        number = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError, OverflowError):
        return default
    return max(minimum, min(maximum, number))


_PIPELINE_STATUS_HOST = "raw.githubusercontent.com"
_PIPELINE_STATUS_PATH = "/oceanhong970201/Free-Proxy/master/output/pipeline-status.json"


def _safe_pipeline_status_url(value: object) -> str:
    """Return one normalized public artifact URL or an empty disabled value.

    The dashboard never accepts a URL from an HTTP request. Configuration is
    still validated defensively: restricting the origin and artifact filename
    prevents a typo or hostile local config from turning status refresh into an
    SSRF primitive. Query strings are unnecessary for this public artifact and
    could otherwise conceal credentials.
    """
    if not isinstance(value, str):
        return ""
    candidate = value.strip()
    if not candidate or len(candidate) > 2048:
        return ""
    try:
        parsed = urlparse(candidate)
        port = parsed.port
    except ValueError:
        return ""
    hostname = (parsed.hostname or "").casefold().rstrip(".")
    if (
        parsed.scheme.casefold() != "https"
        or hostname != _PIPELINE_STATUS_HOST
        or port is not None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.params
        or parsed.query
        or parsed.fragment
        or parsed.path != _PIPELINE_STATUS_PATH
    ):
        return ""
    return f"https://{_PIPELINE_STATUS_HOST}{_PIPELINE_STATUS_PATH}"


def load_dashboard_config(root: Path) -> DashboardConfig:
    path = root / "config" / "dashboard.yaml"
    document: dict[str, Any] = {}
    if path.exists():
        loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if isinstance(loaded, dict):
            document = loaded
    checker = document.get("ip_checker") or {}
    if not isinstance(checker, dict):
        checker = {}
    return DashboardConfig(
        worker_url=str(document.get("worker_url") or "").strip().rstrip("/"),
        pipeline_status_url=_safe_pipeline_status_url(
            document.get("pipeline_status_url")
        ),
        refresh_seconds=max(5, int(document.get("refresh_seconds", 30))),
        remote_timeout_seconds=max(
            1.0, float(document.get("remote_timeout_seconds", 8.0))
        ),
        pipeline_status_timeout_seconds=_clamped_float(
            document.get("pipeline_status_timeout_seconds", 5.0),
            5.0,
            1.0,
            15.0,
        ),
        pipeline_status_cache_seconds=_clamped_int(
            document.get("pipeline_status_cache_seconds", 60),
            60,
            5,
            60 * 60,
        ),
        pipeline_status_stale_seconds=_clamped_int(
            document.get("pipeline_status_stale_seconds", 60 * 60),
            60 * 60,
            60,
            7 * 24 * 60 * 60,
        ),
        checker_timeout_seconds=max(5.0, float(checker.get("timeout_seconds", 18.0))),
        checker_concurrency=max(1, min(4, int(checker.get("concurrency", 4)))),
        checker_cache_seconds=max(0, int(checker.get("cache_seconds", 300))),
        purity_timeout_seconds=_clamped_float(
            checker.get("purity_timeout_seconds", 8.0), 8.0, 1.0, 30.0
        ),
        purity_cache_seconds=_clamped_int(
            checker.get("purity_cache_seconds", 24 * 60 * 60),
            24 * 60 * 60,
            0,
            7 * 24 * 60 * 60,
        ),
        purity_provider_concurrency=_clamped_int(
            checker.get("purity_provider_concurrency", 2), 2, 1, 3
        ),
    )


def _iso_timestamp(timestamp: float | int | None) -> str | None:
    if timestamp is None:
        return None
    return datetime.fromtimestamp(float(timestamp), timezone.utc).isoformat()


def _file_age(path: Path, now: float) -> float | None:
    return max(0.0, now - path.stat().st_mtime) if path.exists() else None


_NODE_ID_RE = re.compile(r"^[0-9a-f]{64}$")
_IP_RESULT_STATES = {"passed", "partial", "rotating", "bypass", "failed", "cancelled"}
_IP_RESULT_MODES = {"endpoint", "exit", "purity"}
_IP_RESULT_ERRORS = {
    "node_not_found",
    "unsupported_mode",
    "checker_runtime_unavailable",
    "invalid_proxy_config",
    "proxy_core_exited",
    "proxy_core_timeout",
    "all_ip_probes_failed",
    "invalid_response",
    "cancelled",
    "timeout",
    "invalid_probe_url",
    "curl_cleanup_failed",
    "check_failed",
    "all_reputation_probes_failed",
    "provider_timeout",
    "provider_http_error",
    "provider_invalid_response",
    "provider_response_too_large",
    "provider_unavailable",
    "provider_quota_exhausted",
    "network_error",
    "unsupported_outbound",
    "proxy_runtime_error",
}
_IP_RESULT_PROVIDERS = {"edge-trace", "ip-json"}
_REPUTATION_PROVIDERS = {"network-risk", "network-profile", "proxy-risk"}
_REPUTATION_PROVIDER_STATES = {"ok", "error"}
_PURITY_GRADES = {"A", "B", "C", "D", "F"}
_PURITY_CONFIDENCE = {"high", "medium", "low"}
_PURITY_SIGNALS = {
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
_PURITY_REASONS = _PURITY_SIGNALS | {
    "direct_bypass",
    "rotating_exit",
    "provider_disagreement",
    "limited_provider_coverage",
    "elevated_risk",
    "moderate_risk",
}


def _display_name(proto: object, host: object, port: object) -> str:
    """Build a display label only from non-secret endpoint metadata.

    Node labels frequently originate from URI fragments and are therefore not
    trustworthy display data: they can contain a whole URI, UUID, or password.
    The dashboard deliberately does not expose those labels.
    """
    protocol = re.sub(r"[^a-zA-Z0-9_.-]", "", str(proto or "node"))[:32] or "node"
    endpoint = re.sub(r"[\s/@?#]", "", str(host or "unknown"))[:253] or "unknown"
    try:
        number = int(port)
    except (TypeError, ValueError):
        number = 0
    return f"{protocol}-{endpoint}:{number}" if number else f"{protocol}-{endpoint}"


def _grade_for_score(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def _column_expression(columns: set[str], column: str) -> str:
    """Select an optional legacy column without interpolating untrusted SQL."""
    if column in columns:
        return f'"{column}" AS "{column}"'
    return f'NULL AS "{column}"'


def _exception_code(exc: BaseException) -> str:
    """Return a stable diagnostic code without echoing parsed source content."""
    name = re.sub(r"[^A-Za-z0-9_]", "", type(exc).__name__)[:64]
    return name or "operation_failed"


def _public_worker_url(value: str) -> str | None:
    """Strip userinfo, path and query data from the browser-visible worker label."""
    try:
        parsed = urlparse(value)
        if not parsed.scheme or not parsed.hostname:
            return None
        host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
        port = f":{parsed.port}" if parsed.port else ""
        return f"{parsed.scheme}://{host}{port}"
    except ValueError:
        return None


def _pipeline_summary(value: dict[str, Any]) -> dict[str, Any]:
    """Expose metrics only; stage errors and arbitrary strings remain server-side."""
    safe_keys = {
        "success",
        "strict",
        "fetched",
        "parsed",
        "raw_nodes",
        "unique",
        "duplicates",
        "verified",
        "alive",
        "dead",
        "tier1_alive",
        "tier2_passed",
        "published",
        "emitted",
        "nodes",
        "sources",
        "http_status",
        "paused",
        "resumed",
    }
    result: dict[str, Any] = {}
    for key in safe_keys:
        item = value.get(key)
        if isinstance(item, bool) or item is None:
            result[key] = item
        elif isinstance(item, (int, float)) and not isinstance(item, bool):
            result[key] = item
    if value.get("error"):
        result["error"] = "stage_failed"
    return result


def _overall_pipeline_status(stages: list[dict[str, Any]]) -> str:
    """Aggregate current stage health separately from the latest command result."""
    statuses = {str(stage.get("status") or "unknown") for stage in stages}
    if statuses & {"failed", "offline"}:
        return "failed"
    if statuses & {"attention", "degraded", "missing"}:
        return "attention"
    if not statuses or "unknown" in statuses:
        return "unknown"
    if statuses <= {"ready", "healthy"}:
        return "healthy"
    return "unknown"


_PIPELINE_STATUS_KEYS = {
    "schema_version",
    "generated_at",
    "pipeline_status",
    "verify",
    "artifacts",
}
_PIPELINE_VERIFY_KEYS = {
    "total",
    "verified",
    "alive",
    "dead",
    "unverified",
    "tier1_alive",
    "tier2_passed",
    "completed",
}
_PIPELINE_ARTIFACT_KEYS = {
    "node_count",
    "clash_proxies",
    "singbox_outbounds",
    "rss_items",
}
_PIPELINE_TIMESTAMP_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z"
)
_MAX_PIPELINE_COUNT = 10_000_000
_MAX_PIPELINE_STATUS_BYTES = 64 * 1024


class _PipelineStatusFetchError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _pipeline_count(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("pipeline status count must be an integer")
    if not 0 <= value <= _MAX_PIPELINE_COUNT:
        raise ValueError("pipeline status count is outside the accepted range")
    return value


def _parse_pipeline_status_document(
    document: object, *, now: float
) -> tuple[dict[str, Any], float]:
    """Validate the closed automation artifact schema and copy safe fields."""
    if not isinstance(document, dict) or set(document) != _PIPELINE_STATUS_KEYS:
        raise ValueError("invalid pipeline status object")
    schema_version = document.get("schema_version")
    if isinstance(schema_version, bool) or schema_version != 1:
        raise ValueError("unsupported pipeline status schema")
    generated_at = document.get("generated_at")
    if not isinstance(generated_at, str) or not _PIPELINE_TIMESTAMP_RE.fullmatch(
        generated_at
    ):
        raise ValueError("invalid pipeline status timestamp")
    try:
        generated_epoch = datetime.fromisoformat(
            generated_at.removesuffix("Z") + "+00:00"
        ).timestamp()
    except ValueError as exc:
        raise ValueError("invalid pipeline status timestamp") from exc
    if generated_epoch > now + 5 * 60:
        raise ValueError("pipeline status timestamp is in the future")
    pipeline_status = document.get("pipeline_status")
    if not isinstance(pipeline_status, str) or pipeline_status not in {
        "healthy",
        "unknown",
    }:
        raise ValueError("invalid pipeline status state")

    verify = document.get("verify")
    if not isinstance(verify, dict) or set(verify) != _PIPELINE_VERIFY_KEYS:
        raise ValueError("invalid pipeline verify summary")
    completed = verify.get("completed")
    if not isinstance(completed, bool) or completed != (pipeline_status == "healthy"):
        raise ValueError("pipeline completion state is inconsistent")
    verify_counts = {
        key: _pipeline_count(verify.get(key))
        for key in _PIPELINE_VERIFY_KEYS - {"completed"}
    }
    if pipeline_status == "healthy" and verify_counts["total"] <= 0:
        raise ValueError("pipeline verification total is empty")
    if verify_counts["verified"] != verify_counts["alive"] + verify_counts["dead"]:
        raise ValueError("pipeline verified count is inconsistent")
    if verify_counts["total"] != (
        verify_counts["verified"] + verify_counts["unverified"]
    ):
        raise ValueError("pipeline total count is inconsistent")
    if verify_counts["tier1_alive"] > verify_counts["alive"]:
        raise ValueError("pipeline tier-one count is inconsistent")
    if verify_counts["tier2_passed"] > verify_counts["tier1_alive"]:
        raise ValueError("pipeline tier-two count is inconsistent")
    if pipeline_status == "healthy" and (
        verify_counts["unverified"] != 0
        or verify_counts["tier1_alive"] != verify_counts["alive"]
    ):
        raise ValueError("healthy pipeline verification is inconsistent")

    artifacts = document.get("artifacts")
    if not isinstance(artifacts, dict) or set(artifacts) != _PIPELINE_ARTIFACT_KEYS:
        raise ValueError("invalid pipeline artifact summary")
    artifact_counts = {
        key: _pipeline_count(artifacts.get(key)) for key in _PIPELINE_ARTIFACT_KEYS
    }
    if (
        artifact_counts["clash_proxies"] != artifact_counts["node_count"]
        or artifact_counts["rss_items"] != artifact_counts["node_count"]
        or artifact_counts["singbox_outbounds"] > artifact_counts["node_count"]
    ):
        raise ValueError("pipeline artifact count is inconsistent")
    if (
        pipeline_status == "healthy"
        and artifact_counts["node_count"] != verify_counts["alive"]
    ):
        raise ValueError("healthy pipeline node count is inconsistent")

    safe_verify = {
        key: verify_counts[key]
        for key in (
            "total",
            "verified",
            "alive",
            "dead",
            "unverified",
            "tier1_alive",
            "tier2_passed",
        )
    }
    safe_verify["completed"] = completed
    safe_artifacts = {
        key: artifact_counts[key]
        for key in (
            "node_count",
            "clash_proxies",
            "singbox_outbounds",
            "rss_items",
        )
    }
    return (
        {
            "schema_version": 1,
            "generated_at": generated_at,
            "pipeline_status": pipeline_status,
            "verify": safe_verify,
            "artifacts": safe_artifacts,
        },
        generated_epoch,
    )


class DashboardService:
    def __init__(self, root: Path, config: DashboardConfig | None = None) -> None:
        self.root = root.resolve()
        self.config = config or load_dashboard_config(self.root)
        self.db_path = self.root / "nodes.db"
        self._node_lock = threading.RLock()
        self._node_signature: tuple[int, int] | None = None
        self._nodes: list[dict[str, Any]] = []
        self._node_models: dict[str, ProxyNode] = {}
        self._remote_lock = threading.Lock()
        self._remote_cached_at = 0.0
        self._remote_cache: dict[str, Any] = {}
        self._pipeline_status_lock = threading.Lock()
        self._pipeline_status_cached_at = 0.0
        self._pipeline_status_last_attempt_at = 0.0
        self._pipeline_status_last_error: str | None = None
        self._pipeline_status_last_good: tuple[dict[str, Any], float, float] | None = (
            None
        )
        self.ip_results_path = self.root / "state" / "ip-check-results.jsonl"
        self._ip_results_lock = threading.RLock()
        self._ip_results_signature: int | None = None
        self._ip_results: dict[str, dict[str, dict[str, Any]]] = {}

    def _published_raw(self) -> set[str]:
        path = self.root / "output" / "v2ray-base64.txt"
        if not path.exists():
            return set()
        try:
            encoded = "".join(path.read_text(encoding="utf-8").split())
            decoded = base64.b64decode(encoded, validate=True).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return set()
        return {line.strip() for line in decoded.splitlines() if line.strip()}

    def _node_cache_key(self) -> tuple[int, int]:
        db_mtime = self.db_path.stat().st_mtime_ns if self.db_path.exists() else 0
        output = self.root / "output" / "v2ray-base64.txt"
        output_mtime = output.stat().st_mtime_ns if output.exists() else 0
        return db_mtime, output_mtime

    def _load_nodes(self) -> None:
        signature = self._node_cache_key()
        with self._node_lock:
            if signature == self._node_signature:
                return
            records: list[dict[str, Any]] = []
            models: dict[str, ProxyNode] = {}
            published = self._published_raw()
            if self.db_path.exists():
                conn = sqlite3.connect(str(self.db_path), timeout=2)
                conn.row_factory = sqlite3.Row
                try:
                    columns = {
                        str(row[1])
                        for row in conn.execute("PRAGMA table_info(nodes)").fetchall()
                    }
                    if "uri" not in columns:
                        rows: list[sqlite3.Row] = []
                    else:
                        wanted = (
                            "uri",
                            "node_json",
                            "source",
                            "alive",
                            "latency_ms",
                            "download_speed",
                            "last_checked",
                            "proto",
                            "host",
                            "port",
                            "country",
                            "id",
                        )
                        select = ", ".join(
                            _column_expression(columns, name) for name in wanted
                        )
                        order = '"id"' if "id" in columns else '"uri"'
                        rows = conn.execute(
                            f"SELECT {select} FROM nodes ORDER BY {order}"
                        ).fetchall()
                except sqlite3.Error:
                    # A partially migrated or concurrently replaced database is
                    # represented as an empty dashboard rather than crashing HTTP.
                    rows = []
                finally:
                    conn.close()
                for row in rows:
                    uri = str(row["uri"] or "")
                    if not uri:
                        continue
                    data: dict[str, Any] = {}
                    if row["node_json"]:
                        try:
                            loaded = json.loads(row["node_json"])
                            if isinstance(loaded, dict):
                                data = loaded
                        except (TypeError, ValueError, json.JSONDecodeError):
                            data = {}
                    data.update(
                        {
                            "raw": uri,
                            "source": row["source"],
                            "alive": (
                                bool(row["alive"]) if row["alive"] is not None else None
                            ),
                            "latency_ms": row["latency_ms"],
                            "download_speed": row["download_speed"],
                        }
                    )
                    try:
                        node = (
                            ProxyNode(**data) if data.get("proto") else parse_uri(uri)
                        )
                    except (TypeError, ValueError):
                        node = None
                    if node is None:
                        continue
                    node.source = str(row["source"] or node.source or "unknown")
                    node.alive = (
                        bool(row["alive"]) if row["alive"] is not None else None
                    )
                    node.latency_ms = row["latency_ms"]
                    node.download_speed = row["download_speed"]
                    node_id = hashlib.sha256(uri.encode("utf-8")).hexdigest()
                    status = (
                        "alive"
                        if node.alive is True
                        else "dead"
                        if node.alive is False
                        else "unverified"
                    )
                    models[node_id] = node
                    records.append(
                        {
                            "id": node_id,
                            "short_id": node_id[:10],
                            "name": _display_name(node.proto, node.host, node.port),
                            "proto": node.proto,
                            "host": node.host,
                            "port": node.port,
                            "source": node.source,
                            "status": status,
                            "alive": node.alive,
                            "latency_ms": node.latency_ms,
                            "download_speed": node.download_speed,
                            "country": row["country"],
                            "last_checked": row["last_checked"],
                            "last_checked_at": _iso_timestamp(row["last_checked"]),
                            "published": uri in published,
                        }
                    )
            self._nodes = records
            self._node_models = models
            self._node_signature = signature

    def node_for_check(self, node_id: str) -> ProxyNode | None:
        self._load_nodes()
        with self._node_lock:
            node = self._node_models.get(node_id)
            return node.model_copy(deep=True) if node else None

    def _load_ip_results(self) -> None:
        with self._ip_results_lock:
            signature = (
                self.ip_results_path.stat().st_mtime_ns
                if self.ip_results_path.exists()
                else 0
            )
            if signature == self._ip_results_signature:
                return
            results: dict[str, dict[str, dict[str, Any]]] = {}
            if self.ip_results_path.exists():
                try:
                    lines = self.ip_results_path.read_text(
                        encoding="utf-8"
                    ).splitlines()
                except OSError:
                    lines = []
                for line in lines:
                    if not line.strip():
                        continue
                    try:
                        item = json.loads(line)
                    except (TypeError, ValueError, json.JSONDecodeError):
                        continue
                    clean = self._sanitize_ip_result(item)
                    if clean is None or clean["status"] == "cancelled":
                        continue
                    bucket = results.setdefault(clean["node_id"], {})
                    current = bucket.get(clean["mode"])
                    if current is None or clean["checked_at"] >= current["checked_at"]:
                        bucket[clean["mode"]] = clean
            self._ip_results = results
            self._ip_results_signature = signature

    @staticmethod
    def _sanitize_ip_result(value: object) -> dict[str, Any] | None:
        """Keep persistence/API data bounded and free of runtime diagnostics."""
        if not isinstance(value, dict):
            return None
        node_id = value.get("node_id")
        mode = value.get("mode")
        status = value.get("status")
        if (
            not isinstance(node_id, str)
            or not _NODE_ID_RE.fullmatch(node_id)
            or mode not in _IP_RESULT_MODES
            or status not in _IP_RESULT_STATES
        ):
            return None
        try:
            checked_at = max(0, int(value.get("checked_at", 0)))
            duration_ms = float(value.get("duration_ms", 0))
        except (TypeError, ValueError):
            return None
        if not math.isfinite(duration_ms):
            return None
        duration_ms = max(0.0, min(duration_ms, 300_000.0))
        result: dict[str, Any] = {
            "node_id": node_id,
            "mode": mode,
            "status": status,
            "checked_at": checked_at,
            "duration_ms": round(duration_ms, 1),
            "cached": bool(value.get("cached", False)),
        }

        def public_ips(items: object) -> list[str]:
            if not isinstance(items, list):
                return []
            result_ips = []
            for item in items[:16]:
                try:
                    address = ipaddress.ip_address(str(item))
                except ValueError:
                    continue
                if address.is_global and not address.is_multicast:
                    result_ips.append(str(address))
            return result_ips

        def error_code(item: object) -> str:
            code = str(item or "").casefold()
            if code in _IP_RESULT_ERRORS or re.fullmatch(r"curl_exit_\d{1,3}", code):
                return code
            return "check_failed"

        for key in ("endpoint_ips", "exit_ips"):
            ips = value.get(key)
            cleaned_ips = public_ips(ips)
            if cleaned_ips:
                result[key] = cleaned_ips
        for key in ("tcp_latency_ms",):
            try:
                if value.get(key) is not None:
                    number = float(value[key])
                    if math.isfinite(number):
                        result[key] = round(max(0.0, min(number, 300_000.0)), 1)
            except (TypeError, ValueError):
                pass
        for key in ("exit_ip",):
            item = value.get(key)
            cleaned_ips = public_ips([item])
            if cleaned_ips:
                result[key] = cleaned_ips[0]
        for key in ("country", "colo"):
            item = value.get(key)
            if isinstance(item, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,16}", item):
                result[key] = item
        if isinstance(value.get("direct_match"), bool):
            result["direct_match"] = value["direct_match"]
        error = value.get("error")
        if isinstance(error, str):
            result["error"] = error_code(error)
        providers = value.get("providers")
        if isinstance(providers, list):
            clean_providers = []
            for item in providers[:4]:
                if not isinstance(item, dict):
                    continue
                provider = item.get("provider")
                if provider not in _IP_RESULT_PROVIDERS:
                    # The two fixed provider labels are intentionally the only
                    # externally persisted names.
                    provider = "unknown"
                provider_result: dict[str, str] = {"provider": str(provider)}
                parsed_ips = public_ips([item.get("ip")])
                if parsed_ips:
                    provider_result["ip"] = parsed_ips[0]
                for key in ("country", "colo"):
                    field = item.get(key)
                    if isinstance(field, str) and re.fullmatch(
                        r"[A-Za-z0-9_-]{1,16}", field
                    ):
                        provider_result[key] = field
                if isinstance(item.get("error"), str):
                    provider_result["error"] = error_code(item["error"])
                clean_providers.append(provider_result)
            result["providers"] = clean_providers

        if mode == "purity":
            confidence = value.get("purity_confidence")
            if isinstance(confidence, str) and confidence in _PURITY_CONFIDENCE:
                result["purity_confidence"] = confidence

            score_value = value.get("purity_score")
            if not isinstance(score_value, bool):
                try:
                    score_number = float(score_value)
                except (TypeError, ValueError):
                    score_number = math.nan
                if math.isfinite(score_number):
                    score = int(round(max(0.0, min(score_number, 100.0))))
                    result["purity_score"] = score
                    result["purity_grade"] = _grade_for_score(score)

            reasons = value.get("purity_reasons")
            if isinstance(reasons, list):
                cleaned_reasons = list(
                    dict.fromkeys(
                        item
                        for item in reasons[:16]
                        if isinstance(item, str) and item in _PURITY_REASONS
                    )
                )
                result["purity_reasons"] = cleaned_reasons

            reputation = value.get("reputation_providers")
            if isinstance(reputation, list):
                clean_reputation: list[dict[str, Any]] = []
                for item in reputation[: len(_REPUTATION_PROVIDERS)]:
                    if not isinstance(item, dict):
                        continue
                    provider = item.get("provider")
                    provider_status = item.get("status")
                    if (
                        provider not in _REPUTATION_PROVIDERS
                        or provider_status not in _REPUTATION_PROVIDER_STATES
                    ):
                        continue
                    provider_result: dict[str, Any] = {
                        "provider": provider,
                        "status": provider_status,
                        "cached": bool(item.get("cached", False)),
                    }
                    risk_value = item.get("risk_score")
                    if not isinstance(risk_value, bool):
                        try:
                            risk_number = float(risk_value)
                        except (TypeError, ValueError):
                            risk_number = math.nan
                        if math.isfinite(risk_number):
                            provider_result["risk_score"] = int(
                                round(max(0.0, min(risk_number, 100.0)))
                            )
                    signals = item.get("signals")
                    if isinstance(signals, list):
                        provider_result["signals"] = list(
                            dict.fromkeys(
                                signal
                                for signal in signals[:16]
                                if isinstance(signal, str) and signal in _PURITY_SIGNALS
                            )
                        )
                    if provider_status == "error" and isinstance(
                        item.get("error"), str
                    ):
                        provider_result["error"] = error_code(item["error"])
                    clean_reputation.append(provider_result)
                result["reputation_providers"] = clean_reputation

            coverage = value.get("provider_coverage")
            if isinstance(coverage, dict):
                try:
                    ok_count = int(coverage.get("ok", 0))
                    total_count = int(coverage.get("total", 0))
                except (TypeError, ValueError):
                    pass
                else:
                    if (
                        not isinstance(coverage.get("ok"), bool)
                        and not isinstance(coverage.get("total"), bool)
                        and 0 <= ok_count <= total_count <= len(_REPUTATION_PROVIDERS)
                    ):
                        result["provider_coverage"] = {
                            "ok": ok_count,
                            "total": total_count,
                        }
        return result

    def persist_ip_result(self, result: dict[str, Any]) -> None:
        """Append one sanitized result while concurrent check workers are active."""
        clean = self._sanitize_ip_result(result)
        # Cancellation is a job event, not a new observation.  Retaining it as
        # the latest per-node result would hide a previously useful score.
        if clean is None or clean["status"] == "cancelled":
            return
        if clean["cached"]:
            return
        encoded = (
            json.dumps(clean, ensure_ascii=False, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        with self._ip_results_lock:
            self.ip_results_path.parent.mkdir(parents=True, exist_ok=True)
            descriptor = os.open(
                self.ip_results_path,
                os.O_WRONLY | os.O_CREAT | os.O_APPEND,
                0o600,
            )
            try:
                os.write(descriptor, encoded)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            bucket = self._ip_results.setdefault(clean["node_id"], {})
            current = bucket.get(clean["mode"])
            if current is None or clean["checked_at"] >= current.get("checked_at", 0):
                bucket[clean["mode"]] = clean
            self._ip_results_signature = self.ip_results_path.stat().st_mtime_ns

    def nodes(
        self,
        *,
        query: str = "",
        status: str = "all",
        proto: str = "all",
        source: str = "all",
        published: str = "all",
        offset: int = 0,
        limit: int = 50,
    ) -> dict[str, Any]:
        self._load_nodes()
        self._load_ip_results()
        needle = query.casefold().strip()
        rows = []
        for item in self._nodes:
            if status != "all" and item["status"] != status:
                continue
            if proto != "all" and item["proto"] != proto:
                continue
            if source != "all" and item["source"] != source:
                continue
            if published == "yes" and not item["published"]:
                continue
            if published == "no" and item["published"]:
                continue
            if (
                needle
                and needle
                not in " ".join(
                    str(item.get(key) or "")
                    for key in ("name", "host", "source", "proto", "short_id")
                ).casefold()
            ):
                continue
            enriched = dict(item)
            checks = self._ip_results.get(item["id"], {})
            legacy_checks = [
                checks[mode] for mode in ("endpoint", "exit") if mode in checks
            ]
            enriched["ip_check"] = (
                max(legacy_checks, key=lambda check: check["checked_at"])
                if legacy_checks
                else None
            )
            enriched["ip_purity"] = checks.get("purity")
            rows.append(enriched)
        rank = {"alive": 0, "unverified": 1, "dead": 2}
        rows.sort(
            key=lambda item: (
                0 if item["published"] else 1,
                rank[item["status"]],
                -(item["download_speed"] or 0),
                item["latency_ms"] if item["latency_ms"] is not None else 10**9,
                item["name"].casefold(),
            )
        )
        total = len(rows)
        offset = max(0, offset)
        limit = max(1, min(200, limit))
        return {
            "items": rows[offset : offset + limit],
            "total": total,
            "offset": offset,
            "limit": limit,
            "facets": {
                "protocols": sorted({item["proto"] for item in self._nodes}),
                "sources": sorted({item["source"] for item in self._nodes}),
            },
        }

    def sources(self) -> list[dict[str, Any]]:
        path = self.root / "state" / "sources.json"
        if not path.exists():
            return []
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (ValueError, json.JSONDecodeError):
            return []
        if not isinstance(document, list):
            return []
        result = []
        for source in document:
            if not isinstance(source, dict):
                continue
            parsed = urlparse(str(source.get("url") or ""))
            result.append(
                {
                    "id": source.get("id"),
                    "enabled": source.get("enabled") is True,
                    "tier": source.get("tier", 3),
                    "format": source.get("format"),
                    "status": source.get("status", "unknown"),
                    "last_fetch": source.get("last_fetch"),
                    "last_fetch_at": _iso_timestamp(source.get("last_fetch")),
                    "last_count": source.get("last_count"),
                    "origin": parsed.hostname or "local",
                    "mirrors": len(source.get("mirrors") or []),
                }
            )
        result.sort(key=lambda item: (not item["enabled"], item["tier"], item["id"]))
        return result

    def _artifact_status(self, now: float) -> list[dict[str, Any]]:
        specs = (
            ("clash", self.root / "output" / "clash.yaml"),
            ("sing-box", self.root / "output" / "singbox.json"),
            ("v2ray", self.root / "output" / "v2ray-base64.txt"),
            ("rss", self.root / "output" / "feed.xml"),
        )
        result = []
        for kind, path in specs:
            valid = False
            count: int | None = None
            error: str | None = None
            try:
                if kind == "clash":
                    document = yaml.safe_load(path.read_text(encoding="utf-8"))
                    proxies = (
                        document.get("proxies") if isinstance(document, dict) else None
                    )
                    if not isinstance(proxies, list):
                        raise ValueError("missing proxies list")
                    count = len(proxies)
                elif kind == "sing-box":
                    document = json.loads(path.read_text(encoding="utf-8"))
                    outbounds = (
                        document.get("outbounds")
                        if isinstance(document, dict)
                        else None
                    )
                    if not isinstance(outbounds, list):
                        raise ValueError("missing outbounds list")
                    count = len(outbounds)
                elif kind == "v2ray":
                    encoded = "".join(path.read_text(encoding="utf-8").split())
                    decoded = base64.b64decode(encoded, validate=True).decode("utf-8")
                    count = sum(1 for line in decoded.splitlines() if line.strip())
                else:
                    tree = ElementTree.fromstring(path.read_text(encoding="utf-8"))
                    count = len(tree.findall("./channel/item"))
                valid = True
            except Exception as exc:  # never return parser snippets or node credentials
                error = _exception_code(exc)
            body = path.read_bytes() if path.exists() else b""
            result.append(
                {
                    "id": kind,
                    "valid": valid,
                    "count": count,
                    "bytes": len(body),
                    "sha256": hashlib.sha256(body).hexdigest() if body else None,
                    "updated_at": _iso_timestamp(path.stat().st_mtime)
                    if path.exists()
                    else None,
                    "age_seconds": _file_age(path, now),
                    "error": error,
                }
            )
        return result

    def _download_pipeline_status(self, url: str) -> object:
        """Download one bounded JSON document from the prevalidated origin."""
        if _safe_pipeline_status_url(url) != url:
            raise _PipelineStatusFetchError("invalid_config")
        timeout = httpx.Timeout(self.config.pipeline_status_timeout_seconds)
        try:
            with httpx.Client(
                follow_redirects=False,
                trust_env=False,
                timeout=timeout,
                headers={
                    "Accept": "application/json",
                    "Accept-Encoding": "identity",
                    "Cache-Control": "no-cache",
                },
            ) as client:
                with client.stream("GET", url) as response:
                    if response.status_code != 200:
                        raise _PipelineStatusFetchError("http_error")
                    declared = response.headers.get("Content-Length")
                    if declared is not None:
                        try:
                            declared_size = int(declared)
                        except ValueError:
                            raise _PipelineStatusFetchError(
                                "invalid_response"
                            ) from None
                        if not 0 <= declared_size <= _MAX_PIPELINE_STATUS_BYTES:
                            raise _PipelineStatusFetchError("response_too_large")
                    body = bytearray()
                    for chunk in response.iter_bytes():
                        body.extend(chunk)
                        if len(body) > _MAX_PIPELINE_STATUS_BYTES:
                            raise _PipelineStatusFetchError("response_too_large")
        except _PipelineStatusFetchError:
            raise
        except httpx.HTTPError as exc:
            raise _PipelineStatusFetchError("network_error") from exc
        try:
            return json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise _PipelineStatusFetchError("invalid_schema") from exc

    def _render_remote_pipeline(
        self,
        document: dict[str, Any],
        generated_epoch: float,
        *,
        now: float,
        fetched_at: float,
        force_stale: bool = False,
        error: str | None = None,
    ) -> dict[str, Any]:
        age_seconds = int(max(0.0, now - generated_epoch))
        stale = force_stale or age_seconds > self.config.pipeline_status_stale_seconds
        result: dict[str, Any] = {
            "configured": True,
            "status": "stale" if stale else document["pipeline_status"],
            "pipeline_status": document["pipeline_status"],
            "stale": stale,
            "generated_at": document["generated_at"],
            "age_seconds": age_seconds,
            "fetched_at": _iso_timestamp(fetched_at),
            "verify": dict(document["verify"]),
            "artifacts": dict(document["artifacts"]),
        }
        if error:
            result["error"] = error
        return result

    @staticmethod
    def _unknown_remote_pipeline(
        *,
        configured: bool,
        fetched_at: float | None = None,
        error: str | None = None,
    ) -> dict[str, Any]:
        result: dict[str, Any] = {
            "configured": configured,
            "status": "unknown",
            "pipeline_status": "unknown",
            "stale": True,
            "generated_at": None,
            "age_seconds": None,
            "fetched_at": _iso_timestamp(fetched_at),
            "verify": None,
            "artifacts": None,
        }
        if error:
            result["error"] = error
        return result

    def _current_remote_pipeline(self, now: float) -> dict[str, Any]:
        if self._pipeline_status_last_good is None:
            return self._unknown_remote_pipeline(
                configured=True,
                fetched_at=self._pipeline_status_last_attempt_at or None,
                error=self._pipeline_status_last_error,
            )
        document, generated_epoch, fetched_at = self._pipeline_status_last_good
        return self._render_remote_pipeline(
            document,
            generated_epoch,
            now=now,
            fetched_at=(
                self._pipeline_status_last_attempt_at
                if self._pipeline_status_last_error
                else fetched_at
            ),
            force_stale=self._pipeline_status_last_error is not None,
            error=self._pipeline_status_last_error,
        )

    def _remote_pipeline_status(self, force: bool = False) -> dict[str, Any]:
        configured_value = self.config.pipeline_status_url
        url = _safe_pipeline_status_url(configured_value)
        if not url:
            return self._unknown_remote_pipeline(
                configured=False,
                error="invalid_config" if configured_value else None,
            )
        now_monotonic = time.monotonic()
        with self._pipeline_status_lock:
            now = time.time()
            if (
                not force
                and self._pipeline_status_cached_at
                and now_monotonic - self._pipeline_status_cached_at
                < self.config.pipeline_status_cache_seconds
            ):
                return self._current_remote_pipeline(now)

            self._pipeline_status_cached_at = now_monotonic
            self._pipeline_status_last_attempt_at = now
            try:
                raw_document = self._download_pipeline_status(url)
                document, generated_epoch = _parse_pipeline_status_document(
                    raw_document,
                    now=now,
                )
            except _PipelineStatusFetchError as exc:
                self._pipeline_status_last_error = exc.code
            except ValueError:
                self._pipeline_status_last_error = "invalid_schema"
            except Exception:
                # Unexpected client/runtime diagnostics are never reflected to
                # the API; retain only a fixed error code.
                self._pipeline_status_last_error = "network_error"
            else:
                self._pipeline_status_last_good = (
                    document,
                    generated_epoch,
                    now,
                )
                self._pipeline_status_last_error = None
            return self._current_remote_pipeline(now)

    def _remote_status(self, force: bool = False) -> dict[str, Any]:
        now = time.monotonic()
        with self._remote_lock:
            if not force and now - self._remote_cached_at < 15:
                return self._remote_cache
            base = self.config.worker_url
            if not base:
                result = {"configured": False, "status": "unknown"}
            else:
                result: dict[str, Any] = {
                    "configured": True,
                    "base_url": _public_worker_url(base),
                    "status": "offline",
                }
                try:
                    started = time.perf_counter()
                    health = httpx.get(
                        f"{base}/health",
                        timeout=self.config.remote_timeout_seconds,
                        follow_redirects=True,
                    )
                    result["health_http_status"] = health.status_code
                    result["latency_ms"] = round(
                        (time.perf_counter() - started) * 1000, 1
                    )
                    try:
                        result["health"] = health.json()
                    except ValueError:
                        result["health"] = None
                except Exception as exc:
                    result["health_error"] = _exception_code(exc)
                try:
                    response = httpx.get(
                        f"{base}/sub?format=clash",
                        headers={"Cache-Control": "no-cache"},
                        timeout=self.config.remote_timeout_seconds,
                        follow_redirects=True,
                    )
                    result["subscription_http_status"] = response.status_code
                    body = response.content
                    result["subscription_bytes"] = len(body)
                    result["subscription_sha256"] = hashlib.sha256(body).hexdigest()
                    document = yaml.safe_load(body.decode("utf-8"))
                    proxies = (
                        document.get("proxies") if isinstance(document, dict) else None
                    )
                    if not isinstance(proxies, list):
                        raise ValueError("Worker subscription is missing proxies")
                    result["subscription_nodes"] = len(proxies)
                    result["subscription_valid"] = response.status_code == 200
                except Exception as exc:
                    result["subscription_valid"] = False
                    result["subscription_error"] = _exception_code(exc)
                health_ok = bool((result.get("health") or {}).get("ok"))
                serving = result.get("subscription_valid") is True
                result["status"] = (
                    "healthy"
                    if health_ok and serving
                    else "degraded"
                    if serving
                    else "offline"
                )
            self._remote_cache = result
            self._remote_cached_at = now
            return result

    def _git_status(self) -> dict[str, Any]:
        def command(*args: str) -> str | None:
            try:
                return subprocess.check_output(
                    ["git", *args],
                    cwd=self.root,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    stderr=subprocess.DEVNULL,
                    timeout=2,
                ).strip()
            except (OSError, subprocess.SubprocessError):
                return None

        return {
            "branch": command("branch", "--show-current"),
            "commit": command("rev-parse", "--short=10", "HEAD"),
            "commit_time": command("show", "-s", "--format=%cI", "HEAD"),
        }

    def _local_verification_status(self, now: float) -> dict[str, Any]:
        counts = Counter(item["status"] for item in self._nodes)
        total = len(self._nodes)
        alive = counts["alive"]
        dead = counts["dead"]
        unverified = counts["unverified"]
        verified = alive + dead
        tier2_passed = 0
        for item in self._nodes:
            if item["status"] != "alive" or item.get("download_speed") is None:
                continue
            try:
                speed = float(item["download_speed"])
            except (TypeError, ValueError):
                continue
            if math.isfinite(speed):
                tier2_passed += 1

        completed = total > 0 and verified == total
        updated_candidates: list[float] = []
        live_path = self.root / "state" / "live.jsonl"
        if live_path.exists():
            updated_candidates.append(live_path.stat().st_mtime)
        for item in self._nodes:
            value = item.get("last_checked")
            if value is None or isinstance(value, bool):
                continue
            try:
                checked_at = float(value)
            except (TypeError, ValueError):
                continue
            if math.isfinite(checked_at) and checked_at >= 0:
                updated_candidates.append(checked_at)
        updated_at = max(updated_candidates, default=None)
        return {
            "status": (
                "healthy" if completed else "attention" if verified > 0 else "unknown"
            ),
            "total": total,
            "verified": verified,
            "alive": alive,
            "dead": dead,
            "unverified": unverified,
            "tier1_alive": alive,
            "tier2_passed": min(tier2_passed, alive),
            "completed": completed,
            "updated_at": _iso_timestamp(updated_at),
            "age_seconds": (
                int(max(0.0, now - updated_at)) if updated_at is not None else None
            ),
        }

    def status(self, force_remote: bool = False) -> dict[str, Any]:
        now = time.time()
        self._load_nodes()
        sources = self.sources()
        artifacts = self._artifact_status(now)
        remote = self._remote_status(force=force_remote)
        remote_pipeline = self._remote_pipeline_status(force=force_remote)
        counts = Counter(item["status"] for item in self._nodes)
        local_verification = self._local_verification_status(now)
        protocols = Counter(item["proto"] for item in self._nodes)
        latencies = [
            int(item["latency_ms"])
            for item in self._nodes
            if item["latency_ms"] is not None
        ]
        speeds = [
            float(item["download_speed"])
            for item in self._nodes
            if item["download_speed"] is not None
        ]
        last_run_path = self.root / "state" / "last-run.json"
        last_run: dict[str, Any] | None = None
        if last_run_path.exists():
            try:
                loaded = json.loads(last_run_path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    last_run = loaded
            except (ValueError, json.JSONDecodeError):
                last_run = None
        latest_summary: dict[str, Any] = {}
        if last_run and isinstance(last_run.get("counts"), dict):
            stage = str(last_run.get("last_stage_cmd") or "")
            candidate = last_run["counts"].get(stage)
            if isinstance(candidate, dict):
                latest_summary = candidate
        latest_pipeline_status = (
            "failed"
            if latest_summary.get("success") is False or latest_summary.get("error")
            else "healthy"
            if latest_summary.get("success") is True
            else "unknown"
        )
        staging = self.root / "state" / "staging.jsonl"
        verified = local_verification["verified"]
        pipeline = [
            {
                "id": "fetch",
                "status": "ready" if staging.exists() else "missing",
                "updated_at": _iso_timestamp(staging.stat().st_mtime)
                if staging.exists()
                else None,
                "age_seconds": _file_age(staging, now),
            },
            {
                "id": "parse",
                "status": "ready"
                if self.db_path.exists() and self._nodes
                else "missing",
                "updated_at": _iso_timestamp(self.db_path.stat().st_mtime)
                if self.db_path.exists()
                else None,
                "age_seconds": _file_age(self.db_path, now),
            },
            {
                "id": "verify",
                "status": ("ready" if local_verification["completed"] else "attention"),
                "updated_at": local_verification["updated_at"],
                "verified": verified,
                "total": len(self._nodes),
            },
            {
                "id": "emit",
                "status": "ready"
                if artifacts and all(a["valid"] for a in artifacts)
                else "attention",
                "updated_at": max(
                    (a["updated_at"] for a in artifacts if a["updated_at"]),
                    default=None,
                ),
                "nodes": next(
                    (a["count"] for a in artifacts if a["id"] == "clash"), None
                ),
            },
            {
                "id": "worker",
                "status": remote.get("status", "unknown"),
                "updated_at": _iso_timestamp(now),
                "nodes": remote.get("subscription_nodes"),
            },
        ]
        latest_run = {
            "status": latest_pipeline_status,
            "command": last_run.get("last_stage_cmd") if last_run else None,
            "timestamp": last_run.get("ts") if last_run else None,
            "updated_at": _iso_timestamp(last_run.get("ts")) if last_run else None,
            "summary": _pipeline_summary(latest_summary),
        }
        return {
            "generated_at": _iso_timestamp(now),
            "refresh_seconds": self.config.refresh_seconds,
            "serving": remote,
            "remote_pipeline": remote_pipeline,
            "local_verification": local_verification,
            "pipeline_status": _overall_pipeline_status(pipeline),
            "latest_run": latest_run,
            # Backward-compatible alias for older local frontends.
            "latest_pipeline": latest_run,
            "nodes": {
                "total": len(self._nodes),
                "alive": counts["alive"],
                "dead": counts["dead"],
                "unverified": counts["unverified"],
                "published": sum(bool(item["published"]) for item in self._nodes),
                "tier2_passed": len(speeds),
                "median_latency_ms": round(median(latencies), 1) if latencies else None,
                "median_download_speed": round(median(speeds), 3) if speeds else None,
                "protocols": dict(sorted(protocols.items())),
            },
            "sources": {
                "total": len(sources),
                "enabled": sum(bool(item["enabled"]) for item in sources),
                "disabled": sum(not bool(item["enabled"]) for item in sources),
                "canary": sum("canary" in str(item["status"]) for item in sources),
            },
            "pipeline": pipeline,
            "artifacts": artifacts,
            "git": self._git_status(),
        }
