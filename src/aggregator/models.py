"""pydantic v2 models — ProxyNode + Source (contract-aligned)."""

from __future__ import annotations

from pydantic import BaseModel, Field


class ProxyNode(BaseModel):
    # contract field set — DO NOT reorder (dedup/content_hash depend on shape)
    proto: str  # vmess|vless|trojan|ss|ssr|hysteria2|tuic
    host: str
    port: int
    uuid: str | None = None
    password: str | None = None
    method: str | None = None  # ss cipher
    sni: str | None = None
    net: str | None = None  # ws|tcp|grpc
    path: str | None = None
    host_header: str | None = None
    flow: str | None = None  # vless reality
    fp: str | None = None  # utls fingerprint
    alpn: str | None = None
    pbk: str | None = None  # reality public key
    sid: str | None = None  # reality short id
    raw: str  # original URI / serialized form
    name: str | None = None
    # runtime-only (not in URI): liveness + provenance
    source: str | None = None
    alive: bool | None = None
    latency_ms: int | None = None
    download_speed: float | None = None  # MB/s, Tier 2 download test
    content_hash: str | None = None

    def dedup_key(self) -> str:
        """Level-2 dedup key per contract."""
        import hashlib

        cred = self.uuid or self.password or ""
        sni = self.sni or ""
        return hashlib.sha256(
            f"{self.host}:{self.port}:{self.proto}:{cred}:{sni}".encode()
        ).hexdigest()


class Source(BaseModel):
    id: str
    url: str
    mirrors: list[str] = Field(default_factory=list)
    format: str
    enabled: bool = True
    tier: int = 3
    last_fetch: int | None = None
    last_count: int | None = None
    status: str = "unknown"
