"""G2 公網掃描 agent — masscan/nmap wrapper + 協議辨識 + leads 產出.

規格見 _GRAY_SPEC.md (scan 段) 與 docs/PRD.md 階段 10/A5。

只產 leads: 對配置不當 (無 auth / 預設憑證) 的服務用少量常見默認值重建 URI,
不對有 auth 的服務 brute force, 不主動連線驗證洩漏憑證的服務。
預設 enabled=false; scan_shards.txt 為空 (無授權目標) 時 log + 返回。
"""

from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import logging
import os
import re
import shutil
import subprocess
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import yaml

ROOT = Path(__file__).resolve().parents[2]
SHARDS_FILE = ROOT / "tools" / "scan_shards.txt"
GRAY_CONFIG = ROOT / "config" / "gray_sources.yaml"
GRAY_NODES = ROOT / "state" / "gray_nodes.jsonl"
LEADS_FILE = ROOT / "state" / "recon-leads.jsonl"
CANDIDATE_QUARANTINE = ROOT / "state" / "scan-candidates.jsonl"
GNMAP_OUT = ROOT / "state" / "scan.gnmap"
NMAP_DISCOVERY_OUT = ROOT / "state" / "scan-discovery.xml"
NMAP_OUT = ROOT / "state" / "scan.xml"

logger = logging.getLogger("scanner")

# 協議 -> 常見 TCP 端口 (附錄 C)
PORT_HINTS = {
    "ss": {8388, 8389, 8080, 443},
    "ssr": {8388, 80, 443},
    "vmess": {8080, 2052, 2082, 2086, 2095, 443, 2053, 2083, 2087, 2096, 8443},
    "vless": {443, 8443, 2053},
    "trojan": {443, 8443, 2053},
}
# hysteria2 / tuic 走 UDP, masscan TCP 掃不到, 只記 lead
UDP_LEAD_PORTS = {443, 8443, 4443, 36712, 51820}

DEFAULT_PORTS_TCP = [8388, 443, 8080, 2052, 2083, 2087, 2096, 8443, 7001]
DEFAULT_RATE = 10000
MAX_SCAN_RATE = 10000
MAX_ALLOWLIST_ENTRIES = 4096
MAX_ALLOWLIST_ADDRESSES = 65536

# 少量常見默認憑證 (非字典爆破) — 用於推測為配置不當的服務
SS_DEFAULT_CREDS = [
    ("aes-256-gcm", "shadowsocks"),
    ("aes-256-gcm", "123456"),
    ("chacha20-ietf-poly1305", "password"),
    ("aes-128-gcm", "123456"),
]
TROJAN_DEFAULT_PASSWORDS = ["trojan", "123456", "admin"]
# vmess 全零 UUID 是配置不當常見值; 執行期也從既有 gray_nodes 抓 candidate UUID 重用
VMESS_DEFAULT_UUID = "00000000-0000-0000-0000-000000000000"
VMESS_DEFAULT_PATHS = ["/", "/vmess", "/ws"]

# nginx WS+TLS 特徵 banner
NGINX_WS_HINTS = ("400 bad request", "404 not found", "nginx", "cloudflare")


# --------------------------------------------------------------------------- #
# 配置讀取
# --------------------------------------------------------------------------- #
def _load_scan_config() -> dict:
    """Read and validate the scan section from config/gray_sources.yaml."""
    cfg = {
        "enabled": False,
        "leads_only": True,
        "discovery_engine": "auto",
        "ports_tcp": DEFAULT_PORTS_TCP,
        "ports_udp": [443, 36712, 51820],
        "rate": DEFAULT_RATE,
    }
    if not GRAY_CONFIG.exists():
        return cfg
    try:
        text = GRAY_CONFIG.read_text(encoding="utf-8")
        text = re.sub(r"\$\{(\w+)\}", lambda m: os.environ.get(m.group(1), ""), text)
        document = yaml.safe_load(text) or {}
        scan = document.get("scan", {})
        if not isinstance(scan, dict):
            raise ValueError("scan must be a mapping")
    except Exception as e:  # noqa: BLE001
        logger.warning("無法讀 %s: %s, 用預設", GRAY_CONFIG, e)
        return cfg

    if isinstance(scan.get("enabled"), bool):
        cfg["enabled"] = scan["enabled"]
    if isinstance(scan.get("leads_only"), bool):
        cfg["leads_only"] = scan["leads_only"]
    if isinstance(scan.get("discovery_engine"), str):
        cfg["discovery_engine"] = scan["discovery_engine"].strip().lower()
    if isinstance(scan.get("rate"), int):
        cfg["rate"] = scan["rate"]
    if isinstance(scan.get("ports_tcp"), list):
        try:
            parsed_ports = [int(port) for port in scan["ports_tcp"]]
        except (TypeError, ValueError):
            parsed_ports = []
        if parsed_ports:
            cfg["ports_tcp"] = parsed_ports
    return cfg


def _load_shards(shards_path: Path | None = None) -> list[str]:
    """讀 scan_shards.txt, 回傳非註解非空行."""
    path = shards_path or SHARDS_FILE
    if not path.exists():
        return []
    targets: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        targets.append(s)
    return targets


class AllowlistError(ValueError):
    """Raised when a scan target list is not an explicit, bounded IP allowlist."""


def _normalize_allowlist(targets: list[str]) -> list[str]:
    """Validate and normalize literal IP/CIDR targets.

    Host names and range expressions are intentionally unsupported: resolving a
    name later could expand or change the approved target set. CIDRs must be
    network-aligned, and the combined address count is capped to prevent an
    accidental broad scan.
    """
    if len(targets) > MAX_ALLOWLIST_ENTRIES:
        raise AllowlistError(
            f"allowlist has {len(targets)} entries; maximum is {MAX_ALLOWLIST_ENTRIES}"
        )

    normalized: list[str] = []
    seen: set[str] = set()
    address_count = 0
    for raw_target in targets:
        target = raw_target.strip()
        if not target:
            continue
        try:
            if "/" in target:
                network = ipaddress.ip_network(target, strict=True)
                display = network.with_prefixlen
            else:
                address = ipaddress.ip_address(target)
                network = ipaddress.ip_network(
                    f"{address}/{address.max_prefixlen}", strict=True
                )
                display = str(address)
        except ValueError as exc:
            raise AllowlistError(
                f"invalid target {target!r}; use a literal IP or aligned CIDR"
            ) from exc

        if (
            network.network_address.is_unspecified
            or network.network_address.is_multicast
        ):
            raise AllowlistError(f"unsupported target range {target!r}")
        key = network.with_prefixlen
        if key in seen:
            continue
        seen.add(key)
        address_count += network.num_addresses
        if address_count > MAX_ALLOWLIST_ADDRESSES:
            raise AllowlistError(
                "allowlist is too broad; "
                f"maximum combined size is {MAX_ALLOWLIST_ADDRESSES} addresses"
            )
        normalized.append(display)
    return normalized


def _allowlist_networks(
    targets: list[str],
) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for target in targets:
        if "/" in target:
            networks.append(ipaddress.ip_network(target, strict=True))
        else:
            address = ipaddress.ip_address(target)
            networks.append(
                ipaddress.ip_network(f"{address}/{address.max_prefixlen}", strict=True)
            )
    return networks


def _normalize_ports(ports: list[int]) -> list[int]:
    normalized: set[int] = set()
    for raw_port in ports:
        try:
            port = int(raw_port)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"invalid TCP port {raw_port!r}") from exc
        if not 1 <= port <= 65535:
            raise ValueError(f"TCP port out of range: {port}")
        normalized.add(port)
    if not normalized:
        raise ValueError("at least one TCP port is required")
    return sorted(normalized)


def _filter_open_ports(
    open_ports: list[OpenPort], targets: list[str], ports: list[int]
) -> list[OpenPort]:
    """Fail closed on runner output outside the approved target/port set."""
    networks = _allowlist_networks(targets)
    allowed_ports = set(ports)
    filtered: list[OpenPort] = []
    seen: set[tuple[str, int]] = set()
    for item in open_ports:
        try:
            address = ipaddress.ip_address(item.host)
            port = int(item.port)
        except (AttributeError, TypeError, ValueError):
            continue
        if port not in allowed_ports:
            continue
        if not any(
            address.version == network.version and address in network
            for network in networks
        ):
            continue
        key = (str(address), port)
        if key in seen:
            continue
        seen.add(key)
        filtered.append(OpenPort(host=key[0], port=port))
    return filtered


# --------------------------------------------------------------------------- #
# masscan wrapper
# --------------------------------------------------------------------------- #
@dataclass
class OpenPort:
    host: str
    port: int


def _mass_available() -> bool:
    return shutil.which("masscan") is not None


def run_masscan(targets: list[str], ports: list[int], rate: int) -> list[OpenPort]:
    """呼叫 masscan -p<ports> --rate <rate> -iL <tmp> -oG gnmap; 解析 open.

    不在 PATH -> log + return [].
    """
    try:
        approved_targets = _normalize_allowlist(targets)
    except AllowlistError as exc:
        logger.error("invalid scan allowlist: %s", exc)
        return []
    try:
        approved_ports = _normalize_ports(ports)
    except ValueError as exc:
        logger.error("invalid scan ports: %s", exc)
        return []
    if not approved_targets or not approved_ports:
        logger.info("no approved scan targets or ports")
        return []
    if not 1 <= int(rate) <= MAX_SCAN_RATE:
        logger.error("scan rate must be between 1 and %d", MAX_SCAN_RATE)
        return []
    if not _mass_available():
        logger.warning("masscan 不在 PATH, skip 埠掃階段 (本地多半沒裝)")
        return []

    tmp = ROOT / "state" / "_scan_targets.tmp"
    tmp.parent.mkdir(parents=True, exist_ok=True)
    tmp.write_text("\n".join(approved_targets) + "\n", encoding="utf-8")
    # A failed/aborted scan must never be mistaken for a fresh result.
    GNMAP_OUT.unlink(missing_ok=True)

    port_arg = ",".join(str(p) for p in approved_ports)
    cmd = [
        "masscan",
        f"-p{port_arg}",
        f"--rate={rate}",
        "-iL",
        str(tmp),
        "-oG",
        str(GNMAP_OUT),
        "--interactive=false",
    ]
    logger.info("masscan: %s", " ".join(cmd))
    try:
        # 不可假設環境可拿 root; 失敗 log 不崩
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
    except subprocess.TimeoutExpired:
        logger.warning("masscan 超時 (60min), 放棄本輪")
        return []
    except Exception as e:  # noqa: BLE001
        logger.warning("masscan 執行失敗: %s", e)
        return []
    finally:
        tmp.unlink(missing_ok=True)
    if proc.returncode != 0:
        logger.warning("masscan exit=%d (可能需 root/cap_net_raw)", proc.returncode)
        return []
    return _filter_open_ports(_parse_gnmap(GNMAP_OUT), approved_targets, approved_ports)


def _parse_gnmap(path: Path) -> list[OpenPort]:
    """解析 masscan -oG (gnmap) 輸出取 open host:port.

    行格式: Host: 1.2.3.4 ()	Ports: 8388/open/tcp////
    """
    out: list[OpenPort] = []
    if not path.exists():
        return out
    host_re = re.compile(r"Host:\s+(\S+)")
    port_re = re.compile(r"(\d+)/open/tcp")
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.startswith("Host:") or "Ports:" not in line:
            continue
        hm = host_re.search(line)
        if not hm:
            continue
        host = hm.group(1)
        for pm in port_re.finditer(line):
            out.append(OpenPort(host=host, port=int(pm.group(1))))
    return out


def run_nmap_discovery(
    targets: list[str], ports: list[int], _rate: int = DEFAULT_RATE
) -> list[OpenPort]:
    """Discover open TCP ports with an unprivileged nmap connect scan."""
    try:
        approved_targets = _normalize_allowlist(targets)
        approved_ports = _normalize_ports(ports)
    except (AllowlistError, ValueError) as exc:
        logger.error("invalid nmap discovery input: %s", exc)
        return []
    if not approved_targets or not _nmap_available():
        if approved_targets:
            logger.warning("nmap 不在 PATH, skip connect-scan discovery")
        return []

    NMAP_DISCOVERY_OUT.parent.mkdir(parents=True, exist_ok=True)
    NMAP_DISCOVERY_OUT.unlink(missing_ok=True)
    cmd = [
        "nmap",
        "-sT",
        "-Pn",
        "-n",
        "--open",
        "-p",
        ",".join(str(port) for port in approved_ports),
        "-oX",
        str(NMAP_DISCOVERY_OUT),
    ] + approved_targets
    logger.info("nmap discovery: %d allowlist entries", len(approved_targets))
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
    except subprocess.TimeoutExpired:
        logger.warning("nmap discovery timed out")
        return []
    except Exception as exc:  # noqa: BLE001
        logger.warning("nmap discovery failed: %s", exc)
        return []
    if proc.returncode != 0:
        logger.warning("nmap discovery exit=%d; ignoring output", proc.returncode)
        return []
    discovered = [
        OpenPort(service.host, service.port)
        for service in _parse_nmap_xml(NMAP_DISCOVERY_OUT)
    ]
    return _filter_open_ports(discovered, approved_targets, approved_ports)


def run_discovery(
    targets: list[str],
    ports: list[int],
    rate: int,
    engine: str = "auto",
) -> list[OpenPort]:
    """Select masscan when available, otherwise use bounded nmap discovery."""
    selected = engine.strip().lower()
    if selected == "auto":
        selected = "masscan" if _mass_available() else "nmap"
    if selected == "masscan":
        return run_masscan(targets, ports, rate)
    if selected == "nmap":
        return run_nmap_discovery(targets, ports, rate)
    logger.error("unsupported discovery engine %r", engine)
    return []


# --------------------------------------------------------------------------- #
# nmap -sV wrapper
# --------------------------------------------------------------------------- #
@dataclass
class ServiceInfo:
    host: str
    port: int
    service: str | None = None
    banner: str | None = None
    ssl_cn: str | None = None
    http_title: str | None = None


@dataclass(frozen=True)
class CredentialCandidate:
    host: str
    port: int
    protocol: str
    uri: str


@dataclass(frozen=True)
class CandidateValidation:
    valid: bool
    detail: str | None = None


CredentialValidator = Callable[[CredentialCandidate], CandidateValidation | bool]


def _nmap_available() -> bool:
    return shutil.which("nmap") is not None


def run_nmap(open_ports: list[OpenPort]) -> list[ServiceInfo]:
    """對 open host:port 跑 nmap -sV, 解析 banner/ssl-cert.

    不在 PATH -> log + return [].
    """
    approved: set[tuple[str, int]] = set()
    for item in open_ports:
        try:
            host = str(ipaddress.ip_address(item.host))
            port = int(item.port)
        except (AttributeError, TypeError, ValueError):
            continue
        if 1 <= port <= 65535:
            approved.add((host, port))
    if not approved:
        return []
    if not _nmap_available():
        logger.warning("nmap 不在 PATH, skip 服務指紋階段")
        return []
    host_ports: dict[str, set[int]] = {}
    for host, port in approved:
        host_ports.setdefault(host, set()).add(port)
    groups: dict[tuple[int, tuple[int, ...]], list[str]] = {}
    for host, host_port_set in host_ports.items():
        key = (ipaddress.ip_address(host).version, tuple(sorted(host_port_set)))
        groups.setdefault(key, []).append(host)

    identified: list[ServiceInfo] = []
    logger.info(
        "nmap fingerprint: %d hosts in %d exact-port groups",
        len(host_ports),
        len(groups),
    )
    for (ip_version, exact_ports), group_hosts in groups.items():
        NMAP_OUT.unlink(missing_ok=True)
        cmd = ["nmap"]
        if ip_version == 6:
            cmd.append("-6")
        cmd += [
            "-sT",
            "-sV",
            "-Pn",
            "-n",
            "--open",
            "-p",
            ",".join(str(port) for port in exact_ports),
            "--script",
            "banner,ssl-cert",
            "-oX",
            str(NMAP_OUT),
        ] + sorted(group_hosts)
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
        except subprocess.TimeoutExpired:
            logger.warning("nmap fingerprint timed out for one target group")
            continue
        except Exception as exc:  # noqa: BLE001
            logger.warning("nmap fingerprint failed: %s", exc)
            continue
        if proc.returncode != 0:
            logger.warning(
                "nmap fingerprint exit=%d; ignoring group output", proc.returncode
            )
            continue
        group_approved = {(host, port) for host in group_hosts for port in exact_ports}
        identified.extend(
            service
            for service in _parse_nmap_xml(NMAP_OUT)
            if (service.host, service.port) in group_approved
        )
    return identified


def _parse_nmap_xml(path: Path) -> list[ServiceInfo]:
    """Parse nmap XML for open services and selected script evidence."""
    out: list[ServiceInfo] = []
    if not path.exists():
        return out
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, OSError) as exc:
        logger.warning("invalid nmap XML %s: %s", path, exc)
        return out

    for host_element in root.findall(".//host"):
        address_element = next(
            (
                item
                for item in host_element.findall("address")
                if item.get("addrtype") in (None, "ipv4", "ipv6")
            ),
            None,
        )
        if address_element is None or not address_element.get("addr"):
            continue
        host = address_element.get("addr", "")
        try:
            host = str(ipaddress.ip_address(host))
        except ValueError:
            continue

        for port_element in host_element.findall("./ports/port"):
            state_element = port_element.find("state")
            if state_element is None or state_element.get("state") != "open":
                continue
            try:
                port = int(port_element.get("portid", ""))
            except ValueError:
                continue

            service_element = port_element.find("service")
            service = (
                service_element.get("name") if service_element is not None else None
            )
            banner_parts: list[str] = []
            cn: str | None = None
            title: str | None = None
            for script in port_element.findall("script"):
                script_id = script.get("id", "")
                output = script.get("output", "")
                if script_id in ("banner", "fingerprint-strings") and output:
                    banner_parts.append(output)
                if script_id == "ssl-cert":
                    cn_match = re.search(r"commonName=([^\s,]+)", output)
                    if cn_match:
                        cn = cn_match.group(1)
                if script_id == "http-enum":
                    title_match = re.search(r"Title:\s*([^\r\n,]+)", output)
                    if title_match:
                        title = title_match.group(1).strip()
            out.append(
                ServiceInfo(
                    host=host,
                    port=port,
                    service=service,
                    banner=" | ".join(banner_parts) or None,
                    ssl_cn=cn,
                    http_title=title,
                )
            )
    return out


# --------------------------------------------------------------------------- #
# 協議辨識 + 節點重建
# --------------------------------------------------------------------------- #
def _guess_proto(port: int, svc: ServiceInfo | None) -> str | None:
    """從 port + banner 推測協議. 無法判斷回 None (記 lead)."""
    # banner 顯式特徵優先
    if svc and svc.banner:
        b = svc.banner.lower()
        if any(h in b for h in NGINX_WS_HINTS):
            # 443 + nginx 400/404 -> vmess WS+TLS 或 trojan, 8388 靜默優先 ss
            if port == 8388:
                return "ss"
            if port in PORT_HINTS["trojan"]:
                # trojan 與 vmess 都 443; 有 ssl cert CN 且 path 不明先記 trojan lead
                return "trojan"
            return "vmess"
    # 無 banner (靜默) — port hint
    if port in PORT_HINTS["ss"] and port == 8388:
        return "ss"
    if port in PORT_HINTS["trojan"]:
        return "trojan"
    if port in PORT_HINTS["vmess"]:
        return "vmess"
    return None


def _load_existing_vmess_uuids() -> list[str]:
    """從 gray_nodes.jsonl 既有 vmess URI 抓 UUID 作重用 candidate."""
    uuids: list[str] = []
    if not GRAY_NODES.exists():
        return uuids
    for line in GRAY_NODES.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            if line.startswith("{"):
                record = json.loads(line)
                uri = record.get("raw") or record.get("uri")
            else:
                uri = line
            if not isinstance(uri, str) or not uri.startswith("vmess://"):
                continue
            payload = uri[len("vmess://") :]
            payload += "=" * (-len(payload) % 4)
            obj = json.loads(
                base64.urlsafe_b64decode(payload).decode("utf-8", errors="replace")
            )
            uid = obj.get("id")
            if uid and uid not in uuids and uid != VMESS_DEFAULT_UUID:
                uuids.append(uid)
        except Exception:  # noqa: BLE001
            continue
    return uuids[:20]  # 上限避免太多


def _build_ss_uri(host: str, port: int, method: str, password: str) -> str:
    userinfo = f"{method}:{password}"
    b64 = base64.urlsafe_b64encode(userinfo.encode()).decode().rstrip("=")
    return f"ss://{b64}@{host}:{port}#scan-ss"


def _build_trojan_uri(host: str, port: int, password: str) -> str:
    return (
        f"trojan://{password}@{host}:{port}?"
        f"security=tls&type=tcp&allowInsecure=1#scan-trojan"
    )


def _build_vmess_uri(host: str, port: int, uuid: str, path: str) -> str:
    obj = {
        "v": "2",
        "ps": "scan-vmess",
        "add": host,
        "port": str(port),
        "id": uuid,
        "aid": "0",
        "net": "ws",
        "type": "none",
        "host": host,
        "path": path,
        "tls": "tls",
        "sni": host,
    }
    b64 = (
        base64.urlsafe_b64encode(json.dumps(obj, separators=(",", ":")).encode())
        .decode()
        .rstrip("=")
    )
    return f"vmess://{b64}"


def _reconstruct_nodes(
    services: list[ServiceInfo],
    open_ports: list[OpenPort],
    allow_credential_guesses: bool = False,
    candidate_validator: CredentialValidator | None = None,
    candidate_records: list[dict] | None = None,
) -> tuple[list[str], list[dict]]:
    """對配置不當服務用常見默認值重建 URI.

    Returns: (recovered_uris, leads)
    recovered_uris 只包含注入 validator 明確驗證通過的 URI；仍會先隔離寫入
    gray_nodes.jsonl，不能直接進入發佈流程。
    leads 含所有 host:port + 推測協議 (含未重建的)
    """
    recovered: list[str] = []
    leads: list[dict] = []
    ts = int(time.time())

    # 建立 host:port -> ServiceInfo 索引 (nmap 可能沒對所有 masscan open 結果跑)
    svc_map: dict[tuple[str, int], ServiceInfo] = {}
    for s in services:
        svc_map[(s.host, s.port)] = s

    vmess_uuid_candidates = (
        (_load_existing_vmess_uuids() or [VMESS_DEFAULT_UUID])
        if allow_credential_guesses
        else []
    )

    for op in open_ports:
        svc = svc_map.get((op.host, op.port))
        proto = _guess_proto(op.port, svc)
        lead: dict = {
            "host": op.host,
            "port": op.port,
            "proto_guess": proto,
            "banner": svc.banner if svc else None,
            "ssl_cn": svc.ssl_cn if svc else None,
            "source": "nmap" if svc else "masscan",
            "credential_guess": False,
            "candidate_generated": False,
            "validation_status": "not_requested",
            "recovered": False,
            "ts": ts,
        }

        # The production default is leads-only. Protocol fingerprints are
        # useful evidence, but synthesizing credentials produces unverified
        # node records and must require an explicit configuration opt-in.
        if not allow_credential_guesses:
            leads.append(lead)
            continue

        # 只對無 auth / 預設憑證特徵的服務嘗試重建
        # 判定為「配置不當」: 靜默 ss (8388 open 無 banner) 或
        # nginx WS+TLS 400/404 無明顯真實域名
        has_real_domain = bool(
            svc
            and svc.ssl_cn
            and not svc.ssl_cn.endswith("workers.dev")
            and "." in svc.ssl_cn
            and not svc.ssl_cn.startswith("*")
        )
        cred_guess = False
        uri: str | None = None

        if proto == "ss" and not (svc and svc.banner):
            # 靜默 ss — 嘗試常見默認憑證, 取第一組未重複
            for method, pwd in SS_DEFAULT_CREDS:
                uri = _build_ss_uri(op.host, op.port, method, pwd)
                cred_guess = True
                break

        elif proto == "trojan" and not has_real_domain:
            for pwd in TROJAN_DEFAULT_PASSWORDS:
                uri = _build_trojan_uri(op.host, op.port, pwd)
                cred_guess = True
                break

        elif proto == "vmess" and not has_real_domain:
            # WS+TLS 配置不當: 用候選 UUID + 預設 path
            uid = vmess_uuid_candidates[0]
            for path in VMESS_DEFAULT_PATHS:
                uri = _build_vmess_uri(op.host, op.port, uid, path)
                cred_guess = True
                break

        if uri is not None:
            candidate = CredentialCandidate(
                host=op.host,
                port=op.port,
                protocol=proto or "unknown",
                uri=uri,
            )
            validation_status = "not_run"
            validation_detail = "validator_not_configured"
            validated = False
            if candidate_validator is not None:
                try:
                    result = candidate_validator(candidate)
                    if isinstance(result, CandidateValidation):
                        validated = result.valid
                        validation_detail = result.detail
                    elif isinstance(result, bool):
                        validated = result
                        validation_detail = None
                    else:
                        validation_detail = "validator_returned_invalid_result"
                    validation_status = "verified" if validated else "rejected"
                except Exception as exc:  # noqa: BLE001
                    validation_status = "error"
                    validation_detail = type(exc).__name__

            if candidate_records is not None:
                candidate_records.append(
                    {
                        "raw": uri,
                        "uri": uri,
                        "host": op.host,
                        "port": op.port,
                        "proto": candidate.protocol,
                        "tier": "gray",
                        "source_channel": "scanner",
                        "enabled": False,
                        "watermark_suspect": True,
                        "review_status": "pending",
                        "credential_guess": True,
                        "validation_status": validation_status,
                        "validation_detail": validation_detail,
                        "ts": ts,
                    }
                )
            if validated:
                recovered.append(uri)
                lead["recovered"] = True
            lead["candidate_generated"] = True
            lead["validation_status"] = validation_status
        lead["credential_guess"] = cred_guess
        leads.append(lead)

    return recovered, leads


# --------------------------------------------------------------------------- #
# 輸出
# --------------------------------------------------------------------------- #
def _append_lines(path: Path, lines: list[str]) -> None:
    if not lines:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        for ln in lines:
            f.write(ln.rstrip("\n") + "\n")


def _append_recovered_nodes(uris: list[str]) -> int:
    """Append validator-confirmed candidates, still disabled and quarantined."""
    if not uris:
        return 0
    GRAY_NODES.parent.mkdir(parents=True, exist_ok=True)
    existing: set[str] = set()
    if GRAY_NODES.exists():
        for line in GRAY_NODES.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
                uri = record.get("raw") or record.get("uri")
            except Exception:  # noqa: BLE001
                uri = line
            if isinstance(uri, str):
                existing.add(uri)

    ts = int(time.time())
    written = 0
    with GRAY_NODES.open("a", encoding="utf-8") as handle:
        for uri in uris:
            if not uri or uri in existing:
                continue
            existing.add(uri)
            handle.write(
                json.dumps(
                    {
                        "raw": uri,
                        "uri": uri,
                        "tier": "gray",
                        "source_channel": "scanner",
                        "enabled": False,
                        "watermark_suspect": True,
                        "review_status": "pending",
                        "credential_guess": True,
                        "validation_status": "verified",
                        "ts": ts,
                    },
                    ensure_ascii=False,
                )
                + "\n"
            )
            written += 1
    return written


def _append_candidate_quarantine(records: list[dict]) -> int:
    """Persist generated candidates without enabling or publishing them."""
    if not records:
        return 0
    CANDIDATE_QUARANTINE.parent.mkdir(parents=True, exist_ok=True)
    existing: set[tuple[str, str]] = set()
    if CANDIDATE_QUARANTINE.exists():
        for line in CANDIDATE_QUARANTINE.read_text(
            encoding="utf-8", errors="replace"
        ).splitlines():
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            uri = record.get("uri") or record.get("raw")
            status = record.get("validation_status", "not_run")
            if isinstance(uri, str) and isinstance(status, str):
                existing.add((uri, status))

    written = 0
    with CANDIDATE_QUARANTINE.open("a", encoding="utf-8") as handle:
        for record in records:
            uri = record.get("uri") or record.get("raw")
            status = record.get("validation_status", "not_run")
            key = (uri, status)
            if not isinstance(uri, str) or key in existing:
                continue
            existing.add(key)
            record = dict(record)
            record["enabled"] = False
            record["review_status"] = "pending"
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
            written += 1
    return written


def _write_summary(summary: dict) -> None:
    last_run = ROOT / "state" / "last-run.json"
    try:
        existing = (
            json.loads(last_run.read_text(encoding="utf-8"))
            if last_run.exists()
            else {}
        )
    except Exception:  # noqa: BLE001
        existing = {}
    now = summary.get("ts", int(time.time()))
    existing["scan"] = summary
    stages = existing.get("stages") if isinstance(existing.get("stages"), dict) else {}
    stages["scan-targets"] = {"ts": now, "counts": summary}
    existing["stages"] = stages
    existing["stage"] = 10
    existing["ts"] = now
    existing["last_stage_cmd"] = "scan-targets"
    existing["counts"] = {"scan-targets": summary}
    last_run.write_text(
        json.dumps(existing, ensure_ascii=False, indent=2), encoding="utf-8"
    )


# --------------------------------------------------------------------------- #
# 主入口
# --------------------------------------------------------------------------- #
def run(
    shards_file: Path | None = None,
    ports: list[int] | None = None,
    rate: int | None = None,
    enabled_override: bool | None = None,
    leads_only_override: bool | None = None,
    discovery_runner: Callable[[list[str], list[int], int], list[OpenPort]]
    | None = None,
    nmap_runner: Callable[[list[OpenPort]], list[ServiceInfo]] | None = None,
    credential_validator: CredentialValidator | None = None,
) -> dict:
    """執行完整掃描流程; 回傳 summary dict.

    Args:
        shards_file: 覆蓋 scan_shards.txt 路徑
        ports: 覆蓋 TCP ports
        rate: 覆蓋 masscan --rate
        enabled_override: 覆蓋 config 的 scan.enabled (主要給 CLI/--force 用)
        leads_only_override: 僅供明確的本地測試/呼叫端覆蓋 leads_only
        discovery_runner/nmap_runner/credential_validator: 可注入的本地 fixture hooks
    """
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    cfg = _load_scan_config()
    enabled = bool(enabled_override) if enabled_override is not None else cfg["enabled"]
    if not enabled:
        logger.info("scan.enabled=false, 不執行公網掃描 (預設安全態)")
        summary = {
            "scanned_ips": 0,
            "open_ports": 0,
            "services_identified": 0,
            "nodes_recovered": 0,
            "leads": 0,
            "success": True,
            "skipped": True,
            "reason": "disabled",
            "ts": int(time.time()),
        }
        _write_summary(summary)
        return summary

    shards_path = shards_file or SHARDS_FILE
    targets = _load_shards(shards_path)
    if not targets:
        logger.info("no scan targets (%s 為空或全為註解)", shards_path)
        summary = {
            "scanned_ips": 0,
            "open_ports": 0,
            "services_identified": 0,
            "nodes_recovered": 0,
            "leads": 0,
            "success": True,
            "skipped": True,
            "reason": "no_targets",
            "ts": int(time.time()),
        }
        _write_summary(summary)
        return summary

    try:
        approved_targets = _normalize_allowlist(targets)
    except AllowlistError as exc:
        logger.error("scan refused: %s", exc)
        summary = {
            "scanned_ips": 0,
            "open_ports": 0,
            "services_identified": 0,
            "nodes_recovered": 0,
            "leads": 0,
            "success": False,
            "skipped": True,
            "reason": "invalid_targets",
            "error": str(exc),
            "ts": int(time.time()),
        }
        _write_summary(summary)
        return summary

    try:
        use_ports = _normalize_ports(
            ports if ports is not None else cfg.get("ports_tcp", DEFAULT_PORTS_TCP)
        )
        use_rate = int(cfg.get("rate", DEFAULT_RATE) if rate is None else rate)
        if not 1 <= use_rate <= MAX_SCAN_RATE:
            raise ValueError(f"scan rate must be between 1 and {MAX_SCAN_RATE}")
    except (TypeError, ValueError) as exc:
        logger.error("scan refused: %s", exc)
        summary = {
            "scanned_ips": len(approved_targets),
            "open_ports": 0,
            "services_identified": 0,
            "nodes_recovered": 0,
            "leads": 0,
            "success": False,
            "skipped": True,
            "reason": "invalid_scan_options",
            "error": str(exc),
            "ts": int(time.time()),
        }
        _write_summary(summary)
        return summary

    leads_only = (
        bool(leads_only_override)
        if leads_only_override is not None
        else bool(cfg.get("leads_only", True))
    )
    engine = str(cfg.get("discovery_engine", "auto")).strip().lower()
    if engine not in {"auto", "masscan", "nmap"}:
        summary = {
            "scanned_ips": len(approved_targets),
            "open_ports": 0,
            "services_identified": 0,
            "nodes_recovered": 0,
            "leads": 0,
            "success": False,
            "skipped": True,
            "reason": "invalid_discovery_engine",
            "ts": int(time.time()),
        }
        _write_summary(summary)
        return summary

    if discovery_runner is None:
        if engine == "masscan" and not _mass_available():
            selected_missing = True
        elif engine == "nmap" and not _nmap_available():
            selected_missing = True
        elif engine == "auto" and not (_mass_available() or _nmap_available()):
            selected_missing = True
        else:
            selected_missing = False
        if selected_missing:
            summary = {
                "scanned_ips": len(approved_targets),
                "open_ports": 0,
                "services_identified": 0,
                "nodes_recovered": 0,
                "leads": 0,
                "success": False,
                "skipped": True,
                "reason": "tool_missing",
                "discovery_engine": engine,
                "ts": int(time.time()),
            }
            _write_summary(summary)
            return summary

    logger.info(
        "掃描目標: %d 個 CIDR/IP, ports=%s, rate=%d", len(targets), use_ports, use_rate
    )

    if discovery_runner is None:

        def discovery_runner(
            target_list: list[str], port_list: list[int], scan_rate: int
        ) -> list[OpenPort]:
            return run_discovery(target_list, port_list, scan_rate, engine)

    open_ports = _filter_open_ports(
        discovery_runner(approved_targets, use_ports, use_rate),
        approved_targets,
        use_ports,
    )
    logger.info("discovery 找到 %d 個 approved open host:port", len(open_ports))

    if nmap_runner is None:
        nmap_runner = run_nmap
    services = [
        service
        for service in nmap_runner(open_ports)
        if (service.host, service.port)
        in {(item.host, item.port) for item in open_ports}
    ]
    logger.info("nmap 識別 %d 個服務條目", len(services))

    candidate_records: list[dict] = []
    recovered_uris, leads = _reconstruct_nodes(
        services,
        open_ports,
        allow_credential_guesses=not leads_only,
        candidate_validator=credential_validator,
        candidate_records=candidate_records,
    )

    # 輸出
    quarantined_written = _append_candidate_quarantine(candidate_records)
    recovered_written = _append_recovered_nodes(recovered_uris)
    _append_lines(LEADS_FILE, [json.dumps(lead, ensure_ascii=False) for lead in leads])

    summary = {
        "scanned_ips": len(targets),
        "open_ports": len(open_ports),
        "services_identified": len(services),
        "nodes_recovered": recovered_written,
        "leads": len(leads),
        "leads_only": leads_only,
        "credential_candidates": len(candidate_records),
        "candidates_quarantined": quarantined_written,
        "success": True,
        "skipped": False,
        "reason": "completed",
        "discovery_engine": engine,
        "ts": int(time.time()),
    }
    _write_summary(summary)
    logger.info("summary: %s", summary)
    return summary


def main() -> None:
    ap = argparse.ArgumentParser(description="G2 公網掃描 leads 產出器")
    ap.add_argument(
        "--shards",
        type=Path,
        default=SHARDS_FILE,
        help="掃描目標 CIDR/IP 清單檔 (預設 tools/scan_shards.txt)",
    )
    ap.add_argument(
        "--ports", type=str, default=None, help="覆蓋 TCP ports, 逗號分隔, 如 8388,443"
    )
    ap.add_argument("--rate", type=int, default=None, help="masscan --rate")
    ap.add_argument(
        "--force",
        action="store_true",
        help="忽略 config scan.enabled=false 強制跑 (仍需有授權目標)",
    )
    args = ap.parse_args()

    ports = [int(p) for p in args.ports.split(",") if p.strip()] if args.ports else None
    run(
        shards_file=args.shards,
        ports=ports,
        rate=args.rate,
        enabled_override=True if args.force else None,
    )


if __name__ == "__main__":
    main()
