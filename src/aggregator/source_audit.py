"""Read-only audit of candidate subscription sources.

The normal fetch/parse pipeline deliberately has side effects (it replaces
``staging.jsonl``, ``live.jsonl`` and the SQLite snapshot).  Candidate review
needs a cheaper operation with a much smaller blast radius, so this module is
kept independent from :mod:`aggregator.fetcher` and :mod:`aggregator.cli`.

``run`` reads a candidate registry and an existing live baseline, fetches each
candidate with a bounded response body, parses it through the production
parsers, and writes one atomic JSON report.  No pipeline snapshot is opened for
writing.  Network and verification functions are injectable to make the audit
useful in CI and deterministic in tests.
"""

from __future__ import annotations

import hashlib
import ipaddress
import inspect
import json
import os
import re
import time
import uuid as uuid_module
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence
from urllib.parse import parse_qsl, unquote, urlsplit, urlunsplit

import httpx

from . import dedupe, parser
from .models import STABLE_SAMPLE_SEED, ProxyNode


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_REGISTRY_PATH = ROOT / "state" / "candidates.jsonl"
DEFAULT_BASELINE_PATH = ROOT / "state" / "live.jsonl"
DEFAULT_OUTPUT_PATH = ROOT / "state" / "source-audit.json"
AUDIT_SCHEMA_VERSION = 1

# Keep this in sync with the fetcher's production cap.  The audit has its own
# implementation so a call can never alter staging/source status as a side
# effect.
MAX_RESPONSE_BYTES = 25 * 1024 * 1024
DEFAULT_TIMEOUT_SECONDS = 20.0


def _protected_pipeline_path(path: str | os.PathLike[str]) -> bool:
    """Return whether an audit artifact path is a production projection."""

    try:
        candidate = Path(path).resolve()
        root = ROOT.resolve()
    except OSError:
        return False
    protected = {
        (root / "state" / "live.jsonl").resolve(),
        (root / "state" / "staging.jsonl").resolve(),
        (root / "state" / "sources.json").resolve(),
        (root / "state" / "candidates.jsonl").resolve(),
        (root / "nodes.db").resolve(),
    }
    if candidate in protected:
        return True
    try:
        candidate.relative_to((root / "output").resolve())
        return True
    except (OSError, ValueError):
        return False


def _resolved_path(path: str | os.PathLike[str]) -> Path:
    """Resolve a path for collision checks without requiring it to exist."""

    try:
        return Path(path).resolve()
    except OSError:
        # ``resolve`` can fail for a malformed or inaccessible parent.  An
        # absolute lexical path still gives us a conservative collision check.
        return Path(path).absolute()


def validate_artifact_paths(
    *,
    registry_path: str | os.PathLike[str] | None = None,
    baseline_path: str | os.PathLike[str] | None = None,
    output_path: str | os.PathLike[str] | None = None,
    history_path: str | os.PathLike[str] | None = None,
) -> None:
    """Reject audit destinations that can overwrite an audit input.

    The fixed production paths are guarded by :func:`_protected_pipeline_path`,
    but callers may provide temporary or external baselines.  Pairwise checks
    are therefore required as well: a history file must not replace a custom
    baseline, and the report/history destinations must not replace one another
    or the candidate registry.
    """

    registry = _resolved_path(registry_path) if registry_path is not None else None
    baseline = _resolved_path(baseline_path) if baseline_path is not None else None
    output = _resolved_path(output_path) if output_path is not None else None
    history = _resolved_path(history_path) if history_path is not None else None

    if output is not None and _protected_pipeline_path(output):
        raise ValueError(f"audit output may not overwrite pipeline snapshot: {output}")
    if history is not None and _protected_pipeline_path(history):
        raise ValueError(
            f"audit history may not overwrite pipeline snapshot: {history}"
        )
    if output is not None and baseline is not None and output == baseline:
        raise ValueError("audit output may not overwrite its read-only baseline")
    if history is not None and baseline is not None and history == baseline:
        raise ValueError("audit history may not overwrite its read-only baseline")
    if output is not None and history is not None and output == history:
        raise ValueError("audit output and history must use separate paths")
    if output is not None and registry is not None and output == registry:
        raise ValueError("audit output may not overwrite the candidate registry")
    if history is not None and registry is not None and history == registry:
        raise ValueError("audit history may not overwrite the candidate registry")


_GITHUB_HOSTS = {"github.com", "www.github.com"}
_RAW_HOSTS = {"raw.githubusercontent.com", "raw.github.com"}
_JSDELIVR_HOSTS = {"cdn.jsdelivr.net", "fastly.jsdelivr.net"}
_GH_PROXY_HOSTS = {
    "gh-proxy.com",
    "www.gh-proxy.com",
    "ghproxy.com",
    "www.ghproxy.com",
    "mirror.ghproxy.com",
    "ghfast.top",
    "ghproxy.net",
    "gh-proxy.cc",
    "ghproxy.link",
}
_LOCAL_HOST_SUFFIXES = (
    ".local",
    ".localhost",
    ".internal",
    ".lan",
    ".home.arpa",
)

# Broad URI accounting is separate from the production parser's closed scheme
# set. It lets the audit report unsupported entries instead of silently
# treating them as missing.
_ENTRY_URI_RE = re.compile(
    r"(?<![\w-])[a-z][a-z0-9+.-]{1,20}://[^\s<>]+", re.IGNORECASE
)


def _clean_url(value: str) -> str:
    """Trim common JSON/markdown quoting around a URL."""

    value = str(value or "").strip()
    # A registry occasionally receives a URL copied from a markdown link.
    if value.startswith("<") and value.endswith(">"):
        value = value[1:-1].strip()
    return value.strip("\"'")


def _wrapped_target(url: str) -> str | None:
    """Return a URL hidden behind a known GitHub proxy wrapper."""

    parsed = urlsplit(url)
    host = (parsed.hostname or "").lower()
    if host not in _GH_PROXY_HOSTS:
        return None

    # Both ``/https://raw...`` and ``?url=https://raw...`` are in the wild.
    query_values = dict(parse_qsl(parsed.query, keep_blank_values=True))
    for key in ("url", "uri", "target", "u"):
        target = query_values.get(key)
        if target and re.match(r"^https?://", unquote(target), re.IGNORECASE):
            return _clean_url(unquote(target))

    path = unquote(parsed.path or "").lstrip("/")
    if not path:
        return None
    # Some wrappers turn ``https://`` into ``https:/`` while joining paths.
    if re.match(r"^https?:/[^/]", path, re.IGNORECASE):
        path = path.replace(":/", "://", 1)
    if re.match(r"^https?://", path, re.IGNORECASE):
        return _clean_url(path)
    if path.startswith(("github.com/", "raw.githubusercontent.com/")):
        return "https://" + path
    return None


def _canonical_raw(owner: str, repo: str, ref: str, path: str) -> str:
    """Build a canonical raw.githubusercontent.com URL."""

    pieces = [p for p in (owner, repo, ref, path) if p != ""]
    rendered = "/".join(piece.strip("/") for piece in pieces)
    return f"https://raw.githubusercontent.com/{rendered}"


def canonicalize_url(url: str) -> str:
    """Canonicalize raw GitHub and common mirror URL forms.

    The repository/ref/path case is retained because GitHub paths are
    case-sensitive.  Scheme and host are normalized, fragments and cache
    query parameters are removed for GitHub content, and mirror wrappers are
    recursively unwrapped.  Unknown URL schemes are still normalized rather
    than discarded so callers can report a useful fetch error.
    """

    value = _clean_url(url)
    if not value:
        return ""
    if value.startswith("//"):
        value = "https:" + value
    if not re.match(r"^[a-z][a-z0-9+.-]*://", value, re.IGNORECASE):
        # A bare GitHub URL is convenient in hand-written registries.
        if value.startswith(
            (
                "github.com/",
                "raw.githubusercontent.com/",
                "cdn.jsdelivr.net/",
                "gh-proxy.com/",
                "ghproxy.com/",
                "mirror.ghproxy.com/",
            )
        ):
            value = "https://" + value

    # Unwrap at most a few nested proxy URLs.  A depth limit prevents malformed
    # input from creating an accidental loop.
    for _ in range(4):
        target = _wrapped_target(value)
        if not target:
            break
        value = target

    try:
        parsed = urlsplit(value)
    except ValueError:
        return value
    scheme = (parsed.scheme or "https").lower()
    host = (parsed.hostname or "").lower()
    if not host:
        return value.rstrip("/")

    # GitHub's web raw/blob routes and raw.githubusercontent.com all identify
    # the same content.  Strip query/fragment because ``?raw=1`` and CDN cache
    # keys do not change the file bytes.
    path = unquote(parsed.path or "")
    segments = [segment for segment in path.split("/") if segment]
    if host in _GITHUB_HOSTS and len(segments) >= 4:
        owner, repo, marker = segments[0], segments[1], segments[2].lower()
        if marker in {"raw", "blob"}:
            return _canonical_raw(owner, repo, segments[3], "/".join(segments[4:]))
    if host in _RAW_HOSTS and len(segments) >= 4:
        return _canonical_raw(
            segments[0], segments[1], segments[2], "/".join(segments[3:])
        )
    if host in _JSDELIVR_HOSTS and len(segments) >= 4 and segments[0].lower() == "gh":
        owner, repo_ref = segments[1], segments[2]
        if "@" in repo_ref:
            repo, ref = repo_ref.split("@", 1)
            if repo and ref:
                return _canonical_raw(owner, repo, ref, "/".join(segments[3:]))

    # Generic URL normalization.  Keep meaningful query parameters sorted, but
    # drop fragments and default ports.  This branch also handles ``file://``
    # and local test endpoints without pretending they are GitHub content.
    try:
        port = parsed.port
    except ValueError:
        port = None
    netloc = host
    if parsed.username is not None:
        netloc = f"{parsed.username}@{netloc}"
    if port is not None and not (
        (scheme == "https" and port == 443) or (scheme == "http" and port == 80)
    ):
        netloc += f":{port}"
    normalized_path = re.sub(r"/{2,}", "/", path or "/")
    if normalized_path != "/":
        normalized_path = normalized_path.rstrip("/")
    query = "&".join(
        f"{key}={value}" if value else key
        for key, value in sorted(parse_qsl(parsed.query, keep_blank_values=True))
    )
    return urlunsplit((scheme, netloc, normalized_path, query, ""))


# Compatibility with the existing dedupe helper and callers that use the
# shorter name.
canonical_url = canonicalize_url
canonicalize_source_url = canonicalize_url
canonical_source_url = canonicalize_url
normalize_url = canonicalize_url


def _infer_format(record: Mapping[str, Any], url: str, body: str | None = None) -> str:
    explicit = str(record.get("format") or "").strip().lower()
    aliases = {
        "yaml": "clash",
        "clash.yaml": "clash",
        "clash-yaml": "clash",
        "clash-meta": "clash",
        "mihomo": "clash",
        "mihomo-yaml": "clash",
        "sing-box": "singbox",
        "sing_box": "singbox",
        "singbox-json": "singbox",
        "json": "singbox",
        "base64": "v2ray",
        "v2ray-base64": "v2ray",
        "v2ray_base64": "v2ray",
        "txt": "raw",
        "text": "raw",
        "uri": "raw",
    }
    if explicit:
        return aliases.get(explicit, explicit)
    path = urlsplit(url).path.lower()
    if path.endswith((".yaml", ".yml")):
        return "clash"
    if path.endswith(".json"):
        return "singbox"
    if "base64" in path or path.endswith("/sub") or path.endswith(".b64"):
        return "v2ray"
    if body and body.lstrip().startswith(("{", "[")):
        return "singbox"
    if body:
        if "proxies:" in body[:4096] or body.lstrip().startswith("proxy-groups:"):
            return "clash"
        try:
            decoded = getattr(parser, "_b64decode_loose", lambda value: "")(
                body.strip()
            )
        except Exception:
            decoded = ""
        if "://" in decoded:
            return "v2ray"
    return "raw"


def load_candidates(path: str | os.PathLike[str] | None = None) -> list[dict[str, Any]]:
    """Load candidate records from JSONL, JSON arrays, or wrapper objects."""

    registry_path = Path(path) if path is not None else DEFAULT_REGISTRY_PATH
    if not registry_path.exists():
        return []
    text = registry_path.read_text(encoding="utf-8")
    records: list[Any] = []
    stripped = text.lstrip()
    if stripped.startswith("[") or stripped.startswith("{"):
        try:
            value = json.loads(text)
        except json.JSONDecodeError:
            value = None
        if isinstance(value, list):
            records = value
        elif isinstance(value, dict):
            for key in ("candidates", "items", "sources", "records"):
                if isinstance(value.get(key), list):
                    records = value[key]
                    break
            if not records and value.get("url"):
                records = [value]
    if not records:
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            records.append(value)

    result: list[dict[str, Any]] = []
    for index, value in enumerate(records):
        if not isinstance(value, Mapping):
            continue
        record = dict(value)
        url = _clean_url(str(record.get("url") or record.get("canonical") or ""))
        if not url:
            continue
        record["url"] = url
        record["canonical"] = canonicalize_url(url)
        record["canonical_url"] = record["canonical"]
        candidate_id = str(record.get("id") or f"candidate-{index + 1}")
        record["id"] = candidate_id
        mirrors = record.get("mirrors")
        if isinstance(mirrors, str):
            mirrors = [mirrors]
        if not isinstance(mirrors, Sequence):
            mirrors = []
        record["mirrors"] = [
            _clean_url(str(mirror)) for mirror in mirrors if _clean_url(str(mirror))
        ]
        result.append(record)
    return result


@dataclass
class FetchResult:
    """A small serializable result from the bounded HTTP reader."""

    url: str
    ok: bool
    text: str = ""
    status_code: int | None = None
    bytes_read: int = 0
    content_type: str | None = None
    final_url: str | None = None
    error: str | None = None
    too_large: bool = False
    body_sha256: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "ok": self.ok,
            "status_code": self.status_code,
            "bytes": self.bytes_read,
            "bytes_read": self.bytes_read,
            "content_type": self.content_type,
            "final_url": self.final_url,
            "error": self.error,
            "too_large": self.too_large,
            "body_sha256": self.body_sha256,
        }


def fetch_url(
    url: str,
    *,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    max_bytes: int = MAX_RESPONSE_BYTES,
    client: httpx.Client | None = None,
    headers: Mapping[str, str] | None = None,
) -> FetchResult:
    """Fetch one URL without ever retaining more than ``max_bytes``.

    A ``Content-Length`` larger than the cap is rejected before reading.  For
    chunked responses, the stream is stopped as soon as the next chunk would
    exceed the cap.
    """

    source_url = _clean_url(url)
    if not source_url:
        return FetchResult(source_url, False, error="empty URL")
    scheme = urlsplit(source_url).scheme.lower()
    if scheme not in {"http", "https"}:
        return FetchResult(
            source_url, False, error=f"unsupported URL scheme: {scheme or '<empty>'}"
        )

    own_client = client is None
    http_client = client or httpx.Client(
        follow_redirects=True,
        timeout=timeout,
        headers=dict(headers or {"User-Agent": "free-proxy-source-audit/1"}),
    )
    try:
        try:
            stream = http_client.stream("GET", source_url, timeout=timeout)
            response_context = stream
            response = stream.__enter__() if hasattr(stream, "__enter__") else stream
            should_exit = hasattr(stream, "__exit__")
        except Exception as exc:  # pragma: no cover - exercised by network failures
            return FetchResult(source_url, False, error=f"{type(exc).__name__}: {exc}")

        try:
            status_code = getattr(response, "status_code", None)
            headers_obj = getattr(response, "headers", {}) or {}
            content_length_raw = (
                headers_obj.get("content-length")
                if hasattr(headers_obj, "get")
                else None
            )
            try:
                content_length = (
                    int(content_length_raw) if content_length_raw is not None else None
                )
            except (TypeError, ValueError):
                content_length = None
            if content_length is not None and content_length > max_bytes:
                return FetchResult(
                    source_url,
                    False,
                    status_code=status_code,
                    bytes_read=content_length,
                    final_url=str(getattr(response, "url", "") or "") or None,
                    error=f"response exceeds {max_bytes} bytes",
                    too_large=True,
                )
            if status_code is not None and not 200 <= int(status_code) < 300:
                return FetchResult(
                    source_url,
                    False,
                    status_code=int(status_code),
                    final_url=str(getattr(response, "url", "") or "") or None,
                    error=f"HTTP {status_code} (expected 2xx)",
                )

            body = bytearray()
            iterator = (
                response.iter_bytes()
                if hasattr(response, "iter_bytes")
                else [getattr(response, "content", b"")]
            )
            for chunk in iterator:
                if not chunk:
                    continue
                chunk_bytes = bytes(chunk)
                if len(body) + len(chunk_bytes) > max_bytes:
                    return FetchResult(
                        source_url,
                        False,
                        status_code=int(status_code)
                        if status_code is not None
                        else None,
                        bytes_read=len(body) + len(chunk_bytes),
                        final_url=str(getattr(response, "url", "") or "") or None,
                        error=f"response exceeds {max_bytes} bytes",
                        too_large=True,
                    )
                body.extend(chunk_bytes)
            encoding = getattr(response, "encoding", None) or "utf-8"
            text = bytes(body).decode(encoding, errors="replace")
            if not text.strip():
                return FetchResult(
                    source_url,
                    False,
                    text=text,
                    status_code=int(status_code) if status_code is not None else None,
                    bytes_read=len(body),
                    content_type=headers_obj.get("content-type")
                    if hasattr(headers_obj, "get")
                    else None,
                    final_url=str(getattr(response, "url", "") or "") or None,
                    error="empty body",
                    body_sha256=hashlib.sha256(bytes(body)).hexdigest(),
                )
            return FetchResult(
                source_url,
                True,
                text=text,
                status_code=int(status_code) if status_code is not None else None,
                bytes_read=len(body),
                content_type=headers_obj.get("content-type")
                if hasattr(headers_obj, "get")
                else None,
                final_url=str(getattr(response, "url", "") or "") or None,
                body_sha256=hashlib.sha256(bytes(body)).hexdigest(),
            )
        finally:
            if should_exit:
                response_context.__exit__(None, None, None)
    except Exception as exc:  # pragma: no cover - defensive network boundary
        return FetchResult(source_url, False, error=f"{type(exc).__name__}: {exc}")
    finally:
        if own_client:
            http_client.close()


# Public aliases make the bounded reader easy to inject/use from small CLI
# wrappers without importing the implementation-specific name.
bounded_fetch = fetch_url
fetch = fetch_url


def _coerce_fetch_result(value: Any, url: str, *, max_bytes: int) -> FetchResult:
    """Accept simple injected fetcher return values in tests and integrations."""

    if isinstance(value, FetchResult):
        body = value.text.encode("utf-8")
        measured = max(value.bytes_read, len(body))
        if measured > max_bytes:
            return FetchResult(
                url=value.url or url,
                ok=False,
                status_code=value.status_code,
                bytes_read=measured,
                content_type=value.content_type,
                final_url=value.final_url,
                error=value.error or f"response exceeds {max_bytes} bytes",
                too_large=True,
                body_sha256=value.body_sha256 or hashlib.sha256(body).hexdigest(),
            )
        value.bytes_read = measured
        if value.status_code is not None:
            try:
                status = int(value.status_code)
            except (TypeError, ValueError):
                value.ok = False
                value.error = value.error or "invalid HTTP status"
            else:
                if not 200 <= status < 300:
                    value.ok = False
                    value.error = value.error or f"HTTP {status} (expected 2xx)"
        if value.ok and value.body_sha256 is None:
            value.body_sha256 = hashlib.sha256(body).hexdigest()
        if value.ok and not value.text.strip():
            value.ok = False
            value.error = value.error or "empty body"
        return value
    if hasattr(value, "status_code") and hasattr(value, "text"):
        try:
            body_text = str(value.text or "")
            body_bytes = body_text.encode("utf-8")
            status = int(value.status_code)
            ok = 200 <= status < 300 and bool(body_text.strip())
            too_large = len(body_bytes) > max_bytes
            error = None
            if not 200 <= status < 300:
                error = f"HTTP {status} (expected 2xx)"
            elif not body_text.strip():
                error = "empty body"
            elif too_large:
                error = f"response exceeds {max_bytes} bytes"
            return FetchResult(
                url=url,
                ok=ok and not too_large,
                text=body_text,
                status_code=status,
                bytes_read=len(body_bytes),
                content_type=(getattr(value, "headers", {}) or {}).get("content-type"),
                final_url=str(getattr(value, "url", "") or "") or None,
                error=error,
                too_large=too_large,
                body_sha256=hashlib.sha256(body_bytes).hexdigest(),
            )
        except Exception:
            pass
    if isinstance(value, str):
        raw = value.encode("utf-8")
        if len(raw) > max_bytes:
            return FetchResult(
                url,
                False,
                bytes_read=len(raw),
                error=f"response exceeds {max_bytes} bytes",
                too_large=True,
            )
        return FetchResult(
            url,
            True,
            text=value,
            bytes_read=len(raw),
            body_sha256=hashlib.sha256(raw).hexdigest(),
        )
    if isinstance(value, Mapping):
        text = value.get("text", value.get("body", ""))
        if isinstance(text, bytes):
            text = text.decode("utf-8", errors="replace")
        text = str(text or "")
        ok = bool(value.get("ok", True))
        result = FetchResult(
            str(value.get("url") or url),
            ok,
            text=text,
            status_code=value.get("status_code"),
            bytes_read=int(
                value.get("bytes_read", value.get("bytes", len(text.encode("utf-8"))))
                or 0
            ),
            content_type=value.get("content_type"),
            final_url=value.get("final_url"),
            error=value.get("error"),
            too_large=bool(value.get("too_large", False)),
            body_sha256=value.get("body_sha256"),
        )
        if result.status_code is not None:
            try:
                status = int(result.status_code)
            except (TypeError, ValueError):
                result.ok = False
                result.error = result.error or "invalid HTTP status"
            else:
                if not 200 <= status < 300:
                    result.ok = False
                    result.error = result.error or f"HTTP {status} (expected 2xx)"
        if (
            result.bytes_read > max_bytes
            or len(result.text.encode("utf-8")) > max_bytes
        ):
            result.ok = False
            result.too_large = True
            result.error = result.error or f"response exceeds {max_bytes} bytes"
        if result.ok and not result.text.strip():
            result.ok = False
            result.error = result.error or "empty body"
        if result.ok and result.body_sha256 is None:
            result.body_sha256 = hashlib.sha256(result.text.encode("utf-8")).hexdigest()
        return result
    if isinstance(value, tuple) and len(value) == 2:
        if isinstance(value[0], str) and isinstance(value[1], int):
            return _coerce_fetch_result(
                {
                    "ok": 200 <= value[1] < 300,
                    "text": value[0],
                    "status_code": value[1],
                },
                url,
                max_bytes=max_bytes,
            )
        return _coerce_fetch_result(
            {"ok": True, "text": value[1], "status_code": value[0]},
            url,
            max_bytes=max_bytes,
        )
    return FetchResult(url, False, error="fetcher returned an unsupported result")


def _call_fetcher(
    fetcher: Callable[..., Any], url: str, *, timeout: float, max_bytes: int
) -> FetchResult:
    """Invoke an injected fetcher while tolerating small signature variants."""

    try:
        try:
            value = fetcher(url, timeout=timeout, max_bytes=max_bytes)
        except TypeError:
            try:
                value = fetcher(url, max_bytes=max_bytes)
            except TypeError:
                value = fetcher(url)
        return _coerce_fetch_result(value, url, max_bytes=max_bytes)
    except Exception as exc:
        return FetchResult(url, False, error=f"{type(exc).__name__}: {exc}")


def _parse_nodes(
    format_name: str, text: str
) -> tuple[list[ProxyNode], list[ProxyNode], str | None]:
    try:
        parsed_nodes = parser.parse_raw(format_name, text)
    except Exception as exc:  # parser boundary: one bad source must not abort all
        return [], [], f"{type(exc).__name__}: {exc}"
    try:
        unique, dropped = dedupe.dedupe_nodes(parsed_nodes)
    except Exception as exc:
        return [], [], f"dedupe {type(exc).__name__}: {exc}"
    return unique, dropped, None


def _estimated_entry_count(format_name: str, text: str) -> int | None:
    """Estimate upstream entries so unsupported/invalid content is visible."""

    normalized = str(format_name or "").lower()
    try:
        if normalized == "raw":
            return len(_ENTRY_URI_RE.findall(text))
        if normalized == "v2ray":
            decoded = getattr(parser, "_b64decode_loose", lambda value: "")(
                text.strip()
            )
            decoded_matches = _ENTRY_URI_RE.findall(decoded)
            raw_matches = _ENTRY_URI_RE.findall(text)
            return len(decoded_matches or raw_matches)
        if normalized == "clash":
            import yaml

            document = yaml.safe_load(text)
            proxies = document.get("proxies") if isinstance(document, Mapping) else None
            return len(proxies) if isinstance(proxies, list) else None
        if normalized == "singbox":
            document = json.loads(text)
            outbounds = (
                document.get("outbounds") if isinstance(document, Mapping) else document
            )
            return len(outbounds) if isinstance(outbounds, list) else None
    except (TypeError, ValueError, json.JSONDecodeError):
        return None
    return None


def _node_key(node: ProxyNode) -> str:
    try:
        return node.dedup_key()
    except Exception:
        return dedupe.node_dedup_key(node)


def _semantic_hash(nodes: Iterable[ProxyNode]) -> str:
    values = list(nodes)
    try:
        return dedupe.content_hash(values)
    except Exception:
        keys = sorted({_node_key(node) for node in values})
        return hashlib.sha256("\n".join(keys).encode("utf-8")).hexdigest()


def _key_hash(keys: Iterable[str]) -> str:
    return hashlib.sha256("\n".join(sorted(set(keys))).encode("utf-8")).hexdigest()


def _host_flags(host: str) -> tuple[bool, list[str]]:
    """Classify syntactically private/reserved hosts without DNS lookups."""

    value = str(host or "").strip().strip("[]").rstrip(".")
    lowered = value.lower()
    reasons: list[str] = []
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        address = None
    if address is not None:
        if address.is_private:
            reasons.append("private")
        if address.is_reserved:
            reasons.append("reserved")
        if address.is_loopback:
            reasons.append("loopback")
        if address.is_link_local:
            reasons.append("link_local")
        if address.is_multicast:
            reasons.append("multicast")
        if address.is_unspecified:
            reasons.append("unspecified")
    elif lowered in {"localhost", "localhost.localdomain"} or lowered.endswith(
        _LOCAL_HOST_SUFFIXES
    ):
        reasons.append("private_name")
    return bool(reasons), reasons


def _protocol_counts(nodes: Iterable[ProxyNode]) -> dict[str, int]:
    return dict(
        sorted(Counter((str(node.proto or "").lower() for node in nodes)).items())
    )


def _nodes_by_key(nodes: Iterable[ProxyNode]) -> dict[str, ProxyNode]:
    result: dict[str, ProxyNode] = {}
    for node in nodes:
        result.setdefault(_node_key(node), node)
    return result


def _stable_node_hash(node: ProxyNode) -> str:
    """Match the parser's stable-hash sampling rank."""

    payload = f"{STABLE_SAMPLE_SEED}\0{dedupe.normalize_node(node)}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _stable_sample_nodes(
    nodes: list[ProxyNode], cap: int | None
) -> tuple[list[ProxyNode], int]:
    """Select a deterministic subset while retaining source order in output."""

    if cap is None or len(nodes) <= cap:
        return nodes, 0
    ranked = sorted(
        nodes, key=lambda node: (_stable_node_hash(node), _node_key(node), node.raw)
    )
    selected_keys = {_node_key(node) for node in ranked[:cap]}
    selected = [node for node in nodes if _node_key(node) in selected_keys]
    return selected, len(nodes) - len(selected)


def load_baseline(
    path: str | os.PathLike[str] | None = None,
    *,
    alive_only: bool = False,
) -> tuple[list[ProxyNode], int, str | None]:
    """Read a live JSONL/JSON baseline without modifying it.

    Returns ``(nodes, invalid_records, error)``.  A malformed line is counted
    and skipped so one historical record cannot hide useful overlap data.
    """

    baseline_path = Path(path) if path is not None else DEFAULT_BASELINE_PATH
    if not baseline_path.exists():
        return [], 0, f"baseline not found: {baseline_path}"
    try:
        text = baseline_path.read_text(encoding="utf-8")
    except Exception as exc:
        return [], 0, f"baseline read failed: {type(exc).__name__}: {exc}"
    records: list[Any] = []
    stripped = text.lstrip()
    suffix = baseline_path.suffix.lower()
    structured_format: str | None = None
    if suffix in {".yaml", ".yml"}:
        structured_format = "clash"
    elif suffix == ".json" and (
        "singbox" in baseline_path.name.lower() or "outbound" in stripped[:500].lower()
    ):
        structured_format = "singbox"
    elif suffix == ".txt" and "base64" in baseline_path.name.lower():
        structured_format = "v2ray"
    if structured_format:
        try:
            parsed_nodes = parser.parse_raw(structured_format, text)
        except Exception as exc:
            return [], 0, f"baseline parse failed: {type(exc).__name__}: {exc}"
        if alive_only:
            parsed_nodes = [node for node in parsed_nodes if node.alive is True]
        unique, _ = dedupe.dedupe_nodes(parsed_nodes)
        if not unique:
            return [], 0, "baseline parse produced no nodes"
        return unique, 0, None
    if stripped.startswith("["):
        try:
            value = json.loads(text)
            records = value if isinstance(value, list) else []
        except json.JSONDecodeError:
            records = []
    else:
        for line in text.splitlines():
            if not line.strip():
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                records.append(None)

    nodes: list[ProxyNode] = []
    invalid = 0
    for record in records:
        if not isinstance(record, Mapping):
            invalid += 1
            continue
        if alive_only and record.get("alive") is not True:
            continue
        try:
            node = ProxyNode.model_validate(record)
        except Exception:
            raw = record.get("raw")
            node = parser.parse_uri(str(raw)) if isinstance(raw, str) else None
        if node is None:
            invalid += 1
            continue
        nodes.append(node)
    unique, _ = dedupe.dedupe_nodes(nodes)
    return unique, invalid, None


def _empty_result(
    record: Mapping[str, Any], *, status: str, errors: Sequence[str]
) -> dict[str, Any]:
    empty_hash = _semantic_hash([])
    return {
        "id": str(record.get("id") or ""),
        "candidate_id": str(record.get("id") or ""),
        "source_id": str(record.get("id") or ""),
        "url": str(record.get("url") or ""),
        "canonical": str(
            record.get("canonical") or canonicalize_url(str(record.get("url") or ""))
        ),
        "canonical_url": str(
            record.get("canonical_url") or record.get("canonical") or ""
        ),
        "format": _infer_format(record, str(record.get("url") or "")),
        "status": status,
        "success": False,
        "errors": list(errors),
        "parsed": 0,
        "candidate_entries": None,
        "unsupported_or_invalid": None,
        "unsupported_ratio": None,
        "raw_nodes": 0,
        "raw_bytes": 0,
        "content_sha256": None,
        "unique": 0,
        "node_count": 0,
        "duplicates": 0,
        "capped": False,
        "sampled_out": 0,
        "unique_before_cap": 0,
        "excluded_private_reserved": 0,
        "net_new": 0,
        "net_new_count": 0,
        "overlap": 0,
        "overlap_count": 0,
        "overlap_ratio": 0.0,
        "protocol_counts": {},
        "net_new_protocol_counts": {},
        "overlap_protocol_counts": {},
        "sha256": empty_hash,
        "content_hash": empty_hash,
        "node_set_sha256": _key_hash([]),
        "net_new_sha256": _key_hash([]),
        "overlap_sha256": _key_hash([]),
        "private_or_reserved": False,
        "private_reserved_count": 0,
        "private_reserved_hosts": [],
        "mirror_jaccard": None,
        "mirrors": [],
    }


def _jaccard(left: set[str], right: set[str]) -> float:
    union = left | right
    if not union:
        return 1.0
    return len(left & right) / len(union)


def _invoke_verifier(
    callback: Callable[..., Any], nodes: list[ProxyNode], result: Mapping[str, Any]
) -> Any:
    """Invoke a verifier callback with either nodes or the source result."""

    try:
        signature = inspect.signature(callback)
        positional = [
            parameter
            for parameter in signature.parameters.values()
            if parameter.kind
            in (parameter.POSITIONAL_ONLY, parameter.POSITIONAL_OR_KEYWORD)
        ]
        if len(positional) >= 2:
            return callback(nodes, result)
        if positional and positional[0].name in {
            "result",
            "candidate",
            "record",
            "audit",
        }:
            return callback(result)
    except (TypeError, ValueError):
        pass
    try:
        return callback(nodes)
    except TypeError:
        return callback(result)


def _verification_summary(value: Any, node_count: int) -> dict[str, Any]:
    if value is None:
        return {"status": "ok", "checked": node_count}
    if isinstance(value, Mapping):
        summary = dict(value)
        summary.setdefault("status", "ok")
        summary.setdefault("checked", node_count)
        return summary
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        alive = sum(bool(item) for item in value)
        return {"status": "ok", "checked": len(value), "alive": alive}
    if isinstance(value, bool):
        return {
            "status": "ok",
            "checked": node_count,
            "alive": node_count if value else 0,
        }
    return {"status": "ok", "checked": node_count, "value": value}


DEFAULT_GATE_CONFIG: dict[str, Any] = {
    "min_net_new": 0,
    "max_overlap_ratio": 1.0,
    "max_private_reserved_ratio": 1.0,
    "require_baseline": True,
    "require_fetch": True,
    "require_parse": True,
}


def _evaluate_gate(
    results: Sequence[Mapping[str, Any]],
    totals: Mapping[str, Any],
    config: Mapping[str, Any],
) -> dict[str, Any]:
    reasons: list[str] = []
    if not results:
        reasons.append("no candidates selected")
    if config.get("require_fetch", True):
        failed = [
            str(item.get("id"))
            for item in results
            if item.get("status") in {"fetch_error", "error"}
        ]
        if failed:
            reasons.append("fetch failed: " + ", ".join(failed))
    if config.get("require_parse", True):
        empty = [
            str(item.get("id"))
            for item in results
            if item.get("status") in {"parse_empty", "error"}
        ]
        if empty:
            reasons.append("parser produced no nodes: " + ", ".join(empty))
    try:
        minimum = int(config.get("min_net_new", 0))
    except (TypeError, ValueError):
        minimum = 0
    if int(totals.get("net_new", 0)) < minimum:
        reasons.append(f"net_new {totals.get('net_new', 0)} is below minimum {minimum}")
    unique = int(totals.get("unique", 0) or 0)
    overlap = int(totals.get("overlap", 0) or 0)
    overlap_ratio = overlap / unique if unique else 0.0
    try:
        max_overlap = float(config.get("max_overlap_ratio", 1.0))
    except (TypeError, ValueError):
        max_overlap = 1.0
    if overlap_ratio > max_overlap:
        reasons.append(f"overlap ratio {overlap_ratio:.3f} exceeds {max_overlap:.3f}")
    try:
        max_private = float(config.get("max_private_reserved_ratio", 1.0))
    except (TypeError, ValueError):
        max_private = 1.0
    private_count = int(totals.get("private_reserved_count", 0) or 0)
    private_ratio = min(1.0, private_count / unique) if unique else 0.0
    if private_ratio > max_private:
        reasons.append(
            f"private/reserved ratio {private_ratio:.3f} exceeds {max_private:.3f}"
        )
    return {
        "passed": not reasons,
        "ok": not reasons,
        "config": dict(config),
        "reasons": reasons,
        "overlap_ratio": overlap_ratio,
        "private_reserved_ratio": private_ratio,
    }


def _load_history(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    try:
        text = path.read_text(encoding="utf-8")
    except Exception:
        return []
    if path.suffix.lower() == ".jsonl":
        values: list[dict[str, Any]] = []
        for line in text.splitlines():
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(value, Mapping):
                values.append(dict(value))
        return values
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        return []
    if isinstance(value, list):
        return [dict(item) for item in value if isinstance(item, Mapping)]
    return [dict(value)] if isinstance(value, Mapping) else []


def _write_history(path: Path, entries: Sequence[Mapping[str, Any]]) -> None:
    if _protected_pipeline_path(path):
        raise ValueError(f"audit history may not overwrite pipeline snapshot: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = (
        "\n".join(
            json.dumps(dict(entry), ensure_ascii=False, sort_keys=True)
            for entry in entries
        )
        + "\n"
    )
    tmp = path.with_name(f".{path.name}.{uuid_module.uuid4().hex}.tmp")
    try:
        tmp.write_text(payload, encoding="utf-8")
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


load_history = _load_history
write_history = _write_history


def write_report(
    report: Mapping[str, Any], path: str | os.PathLike[str] | None = None
) -> Path:
    """Atomically write an audit report and return its destination."""

    output_path = Path(path) if path is not None else DEFAULT_OUTPUT_PATH
    if _protected_pipeline_path(output_path):
        raise ValueError(
            f"audit output may not overwrite pipeline snapshot: {output_path}"
        )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = output_path.with_name(f".{output_path.name}.{uuid_module.uuid4().hex}.tmp")
    try:
        with tmp.open("w", encoding="utf-8", newline="\n") as handle:
            json.dump(
                dict(report),
                handle,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
                default=str,
            )
            handle.write("\n")
            handle.flush()
            try:
                os.fsync(handle.fileno())
            except OSError:
                pass
        os.replace(tmp, output_path)
    finally:
        tmp.unlink(missing_ok=True)
    return output_path


def run(
    registry_path: str | os.PathLike[str] | None = None,
    baseline_path: str | os.PathLike[str] | None = None,
    output_path: str | os.PathLike[str] | None = None,
    candidate_ids: Iterable[str] | None = None,
    verify: bool | Callable[..., Any] = False,
    max_nodes: int | None = None,
    history_path: str | os.PathLike[str] | None = None,
    max_nodes_per_source: int | None = None,
    *,
    mirror_jaccard: bool = False,
    include_mirrors: bool | None = None,
    fetch_fn: Callable[..., Any] | None = None,
    fetcher: Callable[..., Any] | None = None,
    verifier: Callable[..., Any] | None = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    max_bytes: int = MAX_RESPONSE_BYTES,
    baseline_alive_only: bool = False,
    exclude_private: bool = False,
    gate_config: Mapping[str, Any] | None = None,
    # Friendly aliases used by a few integrations; the *_path names above are
    # the canonical API and remain positional-compatible.
    registry: str | os.PathLike[str] | None = None,
    baseline: str | os.PathLike[str] | None = None,
    output: str | os.PathLike[str] | None = None,
    http_get: Callable[..., Any] | None = None,
    verify_callback: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Run a read-only candidate source audit.

    ``fetch_fn``/``fetcher`` and ``verifier`` are dependency-injection hooks;
    they are intentionally optional so the cheap audit needs no verifier
    binary.  ``include_mirrors`` is an alias for ``mirror_jaccard`` retained for
    callers that want mirror payloads even when they do not use the metric.
    ``max_nodes_per_source`` supplies a conservative fallback cap for legacy
    candidate records that omit ``max_nodes``.
    """

    if registry is not None:
        registry_path = registry
    if baseline is not None:
        baseline_path = baseline
    if output is not None:
        output_path = output
    if http_get is not None:
        fetch_fn = http_get
    if verify_callback is not None:
        verifier = verify_callback
    if max_bytes is None:
        max_bytes = MAX_RESPONSE_BYTES
    if timeout is None:
        timeout = DEFAULT_TIMEOUT_SECONDS
    if include_mirrors is not None:
        mirror_jaccard = bool(include_mirrors)
    # Normalize implicit destinations before checking collisions.  Otherwise a
    # caller could make a custom baseline collide with the default report by
    # omitting ``output_path``.
    effective_registry_path = (
        registry_path if registry_path is not None else DEFAULT_REGISTRY_PATH
    )
    effective_baseline_path = (
        baseline_path if baseline_path is not None else DEFAULT_BASELINE_PATH
    )
    effective_output_path = (
        output_path if output_path is not None else DEFAULT_OUTPUT_PATH
    )
    validate_artifact_paths(
        registry_path=effective_registry_path,
        baseline_path=effective_baseline_path,
        output_path=effective_output_path,
        history_path=history_path,
    )
    selected_ids = (
        {str(value) for value in candidate_ids} if candidate_ids is not None else None
    )
    records = load_candidates(registry_path)
    selected_records = [
        record
        for record in records
        if selected_ids is None or str(record.get("id")) in selected_ids
    ]

    # Canonical URL dedupe is done before any network request.  Mirrors are
    # merged so a duplicate registry line cannot inflate source counts.
    canonical_records: list[dict[str, Any]] = []
    by_canonical: dict[str, dict[str, Any]] = {}
    registry_duplicates = 0
    for record in selected_records:
        key = str(
            record.get("canonical") or canonicalize_url(str(record.get("url") or ""))
        )
        record["canonical"] = key
        record["canonical_url"] = key
        existing = by_canonical.get(key)
        if existing is None:
            by_canonical[key] = record
            canonical_records.append(record)
            continue
        registry_duplicates += 1
        aliases = list(existing.get("aliases") or [])
        aliases.append(str(record.get("id") or ""))
        existing["aliases"] = aliases
        mirrors = list(existing.get("mirrors") or [])
        for mirror in record.get("mirrors") or []:
            if canonicalize_url(str(mirror)) not in {
                canonicalize_url(str(item)) for item in mirrors
            }:
                mirrors.append(str(mirror))
        existing["mirrors"] = mirrors

    baseline_nodes, baseline_invalid, baseline_error = load_baseline(
        baseline_path, alive_only=baseline_alive_only
    )
    baseline_by_key = _nodes_by_key(baseline_nodes)
    baseline_keys = set(baseline_by_key)
    fetch_callback = fetch_fn or fetcher or fetch_url
    verification_callback = verifier
    if callable(verify):
        verification_callback = verify
    results: list[dict[str, Any]] = []
    all_nodes: dict[str, ProxyNode] = {}
    body_hashes: list[str] = []
    verification_summaries: list[dict[str, Any]] = []

    for record in canonical_records:
        source_url = str(record.get("url") or "")
        mirror_urls: list[str] = []
        mirror_seen: set[str] = set()
        for item in record.get("mirrors") or []:
            mirror_url = _clean_url(str(item))
            if not mirror_url:
                continue
            mirror_key = canonicalize_url(mirror_url) or mirror_url
            if mirror_key in mirror_seen:
                continue
            mirror_seen.add(mirror_key)
            mirror_urls.append(mirror_url)
        # Keep the transport URL as the map key.  Primary and mirror URLs may
        # canonicalize to the same raw GitHub URL, but they still need separate
        # requests when mirror parity is being measured.
        fetched: dict[str, FetchResult] = {}
        primary = _call_fetcher(
            fetch_callback, source_url, timeout=timeout, max_bytes=max_bytes
        )
        fetched[source_url] = primary
        successful = primary if primary.ok else None
        # A mirror is a fallback for a failed primary even in cheap mode.
        if successful is None:
            for mirror_url in mirror_urls:
                if mirror_url in fetched:
                    mirror_result = fetched[mirror_url]
                else:
                    mirror_result = _call_fetcher(
                        fetch_callback, mirror_url, timeout=timeout, max_bytes=max_bytes
                    )
                    fetched[mirror_url] = mirror_result
                if mirror_result.ok:
                    successful = mirror_result
                    break
        # Optional comparison fetches every distinct mirror, not just the
        # fallback selected above.
        if mirror_jaccard:
            for mirror_url in mirror_urls:
                if mirror_url not in fetched:
                    fetched[mirror_url] = _call_fetcher(
                        fetch_callback, mirror_url, timeout=timeout, max_bytes=max_bytes
                    )

        if successful is None:
            errors = [item.error or "fetch failed" for item in fetched.values()]
            result = _empty_result(record, status="fetch_error", errors=errors)
            result["fetch"] = {key: item.as_dict() for key, item in fetched.items()}
            result["fetched"] = False
            results.append(result)
            continue

        # A mirror can be used as a transport fallback, but it cannot prove
        # semantic parity with itself.  Keep this bit separate from
        # ``successful`` so a failed primary is reported as an unavailable
        # Jaccard comparison instead of the misleading value 1.0.
        primary_semantic_available = primary.ok
        body = successful.text
        format_name = _infer_format(record, source_url, body)
        unique_nodes, dropped_nodes, parse_error = _parse_nodes(format_name, body)
        parsed_count = len(unique_nodes) + len(dropped_nodes)
        # A registry record may carry the same per-source cap used by the
        # production parser.  The explicit run argument is the fallback for
        # callers auditing an ad-hoc registry.
        cap_value: int | None = max_nodes_per_source
        if record.get("max_nodes") is not None:
            try:
                record_cap = int(record["max_nodes"])
                cap_value = (
                    record_cap if cap_value is None else min(record_cap, cap_value)
                )
            except (TypeError, ValueError):
                cap_value = max_nodes_per_source
        if max_nodes is not None:
            cap_value = max_nodes if cap_value is None else min(cap_value, max_nodes)
        if cap_value is not None:
            cap_value = max(1, cap_value)
        private_hosts_all: list[str] = []
        private_reasons_all: dict[str, list[str]] = {}
        for node in unique_nodes:
            flagged, reasons = _host_flags(node.host)
            if flagged:
                private_hosts_all.append(node.host)
                private_reasons_all.setdefault(node.host, reasons)
        unique_before_cap = len(unique_nodes)
        # Compare mirrors with the complete semantic source set. A canary cap
        # must not make identical mirrors look divergent merely because only a
        # stable-hash subset is verified.
        mirror_base_keys = {_node_key(node) for node in unique_nodes}
        unique_nodes, sampled_out = _stable_sample_nodes(unique_nodes, cap_value)
        # Match production membership selection before excluding endpoints
        # that must never reach a verifier. A private entry can therefore
        # consume its deterministic slot, and the source-level gate still
        # rejects the candidate rather than silently changing its sample.
        excluded_private = 0
        if exclude_private:
            filtered_nodes: list[ProxyNode] = []
            for node in unique_nodes:
                if _host_flags(node.host)[0]:
                    excluded_private += 1
                else:
                    filtered_nodes.append(node)
            unique_nodes = filtered_nodes
        source_id = str(record.get("id") or "")
        for node in unique_nodes:
            node.source = source_id
        candidate_entries = _estimated_entry_count(format_name, body)
        unsupported_or_invalid = (
            max(0, candidate_entries - parsed_count)
            if candidate_entries is not None
            else None
        )
        unsupported_ratio = (
            unsupported_or_invalid / candidate_entries if candidate_entries else None
        )
        node_map = _nodes_by_key(unique_nodes)
        keys = set(node_map)
        overlap_keys = keys & baseline_keys
        net_new_keys = keys - baseline_keys
        private_hosts: list[str] = list(private_hosts_all)
        private_reasons: dict[str, list[str]] = dict(private_reasons_all)

        mirror_reports: list[dict[str, Any]] = []
        mirror_jaccards: dict[str, float | None] = {}
        mirror_key_sets: list[set[str]] = []
        if mirror_jaccard:
            for mirror_url in mirror_urls:
                mirror_key = canonicalize_url(mirror_url)
                mirror_result = fetched.get(mirror_url)
                if mirror_result is None:
                    continue
                mirror_entry: dict[str, Any] = {
                    "url": mirror_url,
                    "canonical_url": mirror_key,
                    "status": "ok" if mirror_result.ok else "fetch_error",
                    "fetch": mirror_result.as_dict(),
                }
                if mirror_result.ok:
                    mirror_format = _infer_format(
                        record, mirror_url, mirror_result.text
                    )
                    mirror_nodes, mirror_dropped, mirror_error = _parse_nodes(
                        mirror_format, mirror_result.text
                    )
                    mirror_keys = {_node_key(node) for node in mirror_nodes}
                    if primary_semantic_available:
                        mirror_key_sets.append(mirror_keys)
                        value: float | None = _jaccard(mirror_base_keys, mirror_keys)
                    else:
                        value = None
                        mirror_entry["comparison_error"] = (
                            "primary semantic set unavailable"
                        )
                    mirror_jaccards[mirror_url] = value
                    mirror_entry.update(
                        {
                            "parsed": len(mirror_nodes) + len(mirror_dropped),
                            "unique": len(mirror_nodes),
                            "duplicates": len(mirror_dropped),
                            "sha256": _semantic_hash(mirror_nodes),
                            "mirror_jaccard": value,
                        }
                    )
                    if mirror_error:
                        mirror_entry["error"] = mirror_error
                else:
                    mirror_jaccards[mirror_url] = None
                mirror_reports.append(mirror_entry)

        status = "ok"
        errors: list[str] = []
        if parse_error:
            status = "error"
            errors.append(parse_error)
        elif not unique_nodes:
            status = "parse_empty"
            errors.append("parser produced no nodes")
        if successful is not primary:
            errors.append("primary failed; mirror fallback used")

        result = {
            "id": str(record.get("id") or ""),
            "candidate_id": str(record.get("id") or ""),
            "source_id": str(record.get("id") or ""),
            "aliases": list(record.get("aliases") or []),
            "url": source_url,
            "canonical": str(record.get("canonical") or canonicalize_url(source_url)),
            "canonical_url": str(
                record.get("canonical_url") or record.get("canonical") or ""
            ),
            "format": format_name,
            "tier": record.get("tier"),
            "status": status,
            "success": status == "ok",
            "errors": errors,
            "fetched": True,
            "fetched_url": successful.url,
            "http_status": successful.status_code,
            "bytes": successful.bytes_read,
            "raw_bytes": successful.bytes_read,
            "body_sha256": successful.body_sha256,
            "content_sha256": successful.body_sha256,
            "fetch": {key: item.as_dict() for key, item in fetched.items()},
            "parsed": parsed_count,
            "candidate_entries": candidate_entries,
            "unsupported_or_invalid": unsupported_or_invalid,
            "unsupported_ratio": unsupported_ratio,
            "raw_nodes": parsed_count,
            "unique": len(unique_nodes),
            "node_count": len(unique_nodes),
            "duplicates": len(dropped_nodes),
            "capped": bool(sampled_out),
            "sampled_out": sampled_out,
            "unique_before_cap": unique_before_cap,
            "excluded_private_reserved": excluded_private,
            "net_new": len(net_new_keys),
            "net_new_count": len(net_new_keys),
            "overlap": len(overlap_keys),
            "overlap_count": len(overlap_keys),
            "overlap_ratio": len(overlap_keys) / len(keys) if keys else 0.0,
            "protocol_counts": _protocol_counts(unique_nodes),
            "net_new_protocol_counts": _protocol_counts(
                node_map[key] for key in net_new_keys
            ),
            "overlap_protocol_counts": _protocol_counts(
                node_map[key] for key in overlap_keys
            ),
            "sha256": _semantic_hash(unique_nodes),
            "content_hash": _semantic_hash(unique_nodes),
            "node_set_sha256": _key_hash(keys),
            "net_new_sha256": _key_hash(net_new_keys),
            "overlap_sha256": _key_hash(overlap_keys),
            "private_or_reserved": bool(private_hosts),
            "private_reserved_count": len(private_hosts),
            "private_reserved_hosts": sorted(set(private_hosts)),
            "private_reserved_reasons": private_reasons,
            "mirror_jaccard": (
                _jaccard(mirror_base_keys, set().union(*mirror_key_sets))
                if mirror_key_sets
                else None
            ),
            "mirror_jaccards": mirror_jaccards,
            "mirrors": mirror_reports,
        }
        if verification_callback is not None:
            try:
                verification = _verification_summary(
                    _invoke_verifier(verification_callback, unique_nodes, result),
                    len(unique_nodes),
                )
            except Exception as exc:  # verifier errors remain source-local
                verification = {
                    "status": "error",
                    "checked": 0,
                    "error": f"{type(exc).__name__}: {exc}",
                }
            result["verification"] = verification
            verification_summaries.append(verification)
        elif verify:
            result["verification"] = {
                "status": "skipped",
                "checked": 0,
                "reason": "no verifier callback configured",
            }

        for key, node in node_map.items():
            all_nodes.setdefault(key, node)
        if successful.body_sha256:
            body_hashes.append(successful.body_sha256)
        results.append(result)

    union_nodes = list(all_nodes.values())
    union_keys = set(all_nodes)
    union_overlap = union_keys & baseline_keys
    union_net_new = union_keys - baseline_keys
    private_union_count = sum(1 for node in union_nodes if _host_flags(node.host)[0])
    protocol_counts = _protocol_counts(union_nodes)
    net_new_protocol_counts = _protocol_counts(all_nodes[key] for key in union_net_new)
    overlap_protocol_counts = _protocol_counts(all_nodes[key] for key in union_overlap)
    private_observed_count = sum(
        int(item.get("private_reserved_count", 0) or 0) for item in results
    )
    totals: dict[str, Any] = {
        "candidates": len(canonical_records),
        "total_candidates": len(canonical_records),
        "selected_candidates": len(selected_records),
        "registry_records": len(records),
        "registry_duplicates": registry_duplicates,
        "fetched": sum(bool(item.get("fetched")) for item in results),
        "failed": sum(item.get("status") == "fetch_error" for item in results),
        "parse_errors": sum(item.get("status") == "error" for item in results),
        "parsed": sum(int(item.get("parsed", 0) or 0) for item in results),
        "raw_bytes": sum(int(item.get("raw_bytes", 0) or 0) for item in results),
        "candidate_entries": sum(
            int(item.get("candidate_entries", 0) or 0) for item in results
        ),
        "unsupported_or_invalid": sum(
            int(item.get("unsupported_or_invalid", 0) or 0) for item in results
        ),
        "unique": len(union_nodes),
        "node_count": len(union_nodes),
        "total_nodes": len(union_nodes),
        "unique_sum": sum(int(item.get("unique", 0) or 0) for item in results),
        "duplicates": sum(int(item.get("duplicates", 0) or 0) for item in results),
        "sampled_out": sum(int(item.get("sampled_out", 0) or 0) for item in results),
        "excluded_private_reserved": sum(
            int(item.get("excluded_private_reserved", 0) or 0) for item in results
        ),
        "net_new": len(union_net_new),
        "total_net_new": len(union_net_new),
        "net_new_count": len(union_net_new),
        "overlap": len(union_overlap),
        "overlap_count": len(union_overlap),
        "overlap_ratio": len(union_overlap) / len(union_keys) if union_keys else 0.0,
        "protocol_counts": protocol_counts,
        "net_new_protocol_counts": net_new_protocol_counts,
        "overlap_protocol_counts": overlap_protocol_counts,
        "sha256": _semantic_hash(union_nodes),
        "content_hash": _semantic_hash(union_nodes),
        "node_set_sha256": _key_hash(union_keys),
        "net_new_sha256": _key_hash(union_net_new),
        "overlap_sha256": _key_hash(union_overlap),
        "baseline_count": len(baseline_nodes),
        "baseline_invalid": baseline_invalid,
        "baseline_sha256": _semantic_hash(baseline_nodes),
        "private_reserved_count": private_observed_count,
        "selected_private_reserved_count": private_union_count,
        "private_or_reserved": bool(private_observed_count),
        "body_sha256": hashlib.sha256(
            "\n".join(sorted(body_hashes)).encode("ascii")
        ).hexdigest(),
    }
    if totals["candidate_entries"]:
        totals["unsupported_ratio"] = (
            totals["unsupported_or_invalid"] / totals["candidate_entries"]
        )
    else:
        totals["unsupported_ratio"] = None
    config = dict(DEFAULT_GATE_CONFIG)
    if gate_config:
        config.update(dict(gate_config))
    gate = _evaluate_gate(results, totals, config)
    if baseline_error and config.get("require_baseline", True):
        gate["reasons"].append(baseline_error)
        gate["passed"] = False
        gate["ok"] = False
    totals["success"] = bool(canonical_records) and bool(gate["passed"])
    totals["ok"] = totals["success"]

    now = int(time.time())
    run_id = f"{now}-{uuid_module.uuid4().hex[:12]}"
    report: dict[str, Any] = {
        "version": AUDIT_SCHEMA_VERSION,
        "run_id": run_id,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
        "run_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
        "registry_path": str(
            Path(registry_path) if registry_path is not None else DEFAULT_REGISTRY_PATH
        ),
        "baseline_path": str(
            Path(baseline_path) if baseline_path is not None else DEFAULT_BASELINE_PATH
        ),
        "output_path": str(
            Path(output_path) if output_path is not None else DEFAULT_OUTPUT_PATH
        ),
        "baseline_error": baseline_error,
        "baseline_alive_only": baseline_alive_only,
        "max_response_bytes": max_bytes,
        "mirror_jaccard_enabled": mirror_jaccard,
        "exclude_private": exclude_private,
        "verify_enabled": bool(verify),
        "results": results,
        "sources": results,
        "baseline": {
            "path": str(
                Path(baseline_path)
                if baseline_path is not None
                else DEFAULT_BASELINE_PATH
            ),
            "nodes": len(baseline_nodes),
            "invalid": baseline_invalid,
            "sha256": _semantic_hash(baseline_nodes),
            "error": baseline_error,
            "alive_only": baseline_alive_only,
        },
        "totals": totals,
        "gate": gate,
        "gate_config": gate["config"],
        "gate_reasons": gate["reasons"],
        "gate_passed": gate["passed"],
        "success": totals["success"],
        "ok": totals["success"],
    }
    if verify:
        report["verification"] = {
            "enabled": True,
            "status": "ok" if verification_summaries else "skipped",
            "sources": len(verification_summaries),
            "checked": sum(
                int(item.get("checked", 0) or 0) for item in verification_summaries
            ),
        }

    if history_path is not None:
        history_file = Path(history_path)
        previous = _load_history(history_file)
        report["history"] = {
            "path": str(history_file),
            "previous_runs": len(previous),
            "previous_run_id": previous[-1].get("run_id") if previous else None,
        }
        history_entry = {
            "run_id": run_id,
            "generated_at": report["generated_at"],
            "totals": totals,
            "gate_passed": gate["passed"],
            "gate_reasons": gate["reasons"],
        }
        try:
            _write_history(history_file, [*previous, history_entry])
        except Exception as exc:
            report["history"]["error"] = f"{type(exc).__name__}: {exc}"

    destination = write_report(report, output_path)
    report["output_path"] = str(destination)
    return report


audit = run


if __name__ == "__main__":  # pragma: no cover - convenience invocation
    print(json.dumps(run(), ensure_ascii=False, indent=2))
