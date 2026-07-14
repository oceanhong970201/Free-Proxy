"""G2 公網掃描 agent — masscan/nmap wrapper + 協議辨識 + leads 產出.

規格見 _GRAY_SPEC.md (scan 段) 與 docs/PRD.md 階段 10/A5。

只產 leads: 對配置不當 (無 auth / 預設憑證) 的服務用少量常見默認值重建 URI,
不對有 auth 的服務 brute force, 不主動連線驗證洩漏憑證的服務。
預設 enabled=false; scan_shards.txt 為空 (無授權目標) 時 log + 返回。
"""

from __future__ import annotations

import argparse
import base64
import json
import logging
import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SHARDS_FILE = ROOT / "tools" / "scan_shards.txt"
GRAY_CONFIG = ROOT / "config" / "gray_sources.yaml"
GRAY_NODES = ROOT / "state" / "gray_nodes.jsonl"
LEADS_FILE = ROOT / "state" / "recon-leads.jsonl"
GNMAP_OUT = ROOT / "state" / "scan.gnmap"
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
    """讀 config/gray_sources.yaml 的 scan 段; 檔不在則用預設.

    不依賴 PyYAML (可能未裝), 用極簡正則抓 scan 段欄位; 失敗回預設.
    """
    cfg = {
        "enabled": False,
        "ports_tcp": DEFAULT_PORTS_TCP,
        "ports_udp": [443, 36712, 51820],
        "rate": DEFAULT_RATE,
    }
    if not GRAY_CONFIG.exists():
        return cfg
    try:
        text = GRAY_CONFIG.read_text(encoding="utf-8")
    except Exception as e:  # noqa: BLE001
        logger.warning("無法讀 %s: %s, 用預設", GRAY_CONFIG, e)
        return cfg
    # 環境變數替換 ${VAR}
    text = re.sub(r"\$\{(\w+)\}", lambda m: os.environ.get(m.group(1), ""), text)
    # 只看 scan: 區塊 (從 'scan:' 行到下一個同縮排顶层 key 或檔尾)
    m = re.search(r"(?mi)^\s*scan:\s*\n(?P<body>(?:[ \t]+.*\n?)+)", text)
    if not m:
        return cfg
    body = m.group("body")
    kv = re.search(r"(?m)^\s*enabled:\s*(\w+)", body)
    if kv:
        cfg["enabled"] = kv.group(1).strip().lower() in ("true", "1", "yes", "on")
    rate = re.search(r"(?m)^\s*rate:\s*(\d+)", body)
    if rate:
        cfg["rate"] = int(rate.group(1))
    ports = re.search(r"(?m)^\s*ports_tcp:\s*\[([^\]]*)\]", body)
    if ports:
        cfg["ports_tcp"] = [
            int(p) for p in re.findall(r"\d+", ports.group(1)) if p.strip()
        ] or DEFAULT_PORTS_TCP
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
    if not _mass_available():
        logger.warning("masscan 不在 PATH, skip 埠掃階段 (本地多半沒裝)")
        return []
    if not targets:
        logger.info("no scan targets")
        return []

    tmp = ROOT / "state" / "_scan_targets.tmp"
    tmp.parent.mkdir(parents=True, exist_ok=True)
    tmp.write_text("\n".join(targets) + "\n", encoding="utf-8")

    port_arg = ",".join(str(p) for p in ports)
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
    if proc.returncode not in (0,):
        # masscan 對部分 open 回非零, gnmap 仍可能有值; 但常見為權限不足
        logger.warning("masscan exit=%d (可能需 root/cap_net_raw)", proc.returncode)
        if (
            "permission" in (proc.stderr or "").lower()
            or "root" in (proc.stderr or "").lower()
        ):
            logger.warning("masscan 需 root 或 setcap cap_net_raw, 放棄")
            return []
    return _parse_gnmap(GNMAP_OUT)


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


def _nmap_available() -> bool:
    return shutil.which("nmap") is not None


def run_nmap(open_ports: list[OpenPort]) -> list[ServiceInfo]:
    """對 open host:port 跑 nmap -sV, 解析 banner/ssl-cert.

    不在 PATH -> log + return [].
    """
    if not _nmap_available():
        logger.warning("nmap 不在 PATH, skip 服務指紋階段")
        return []
    if not open_ports:
        return []
    hosts = sorted({p.host for p in open_ports})
    cmd = [
        "nmap",
        "-sS",
        "-sV",
        "-Pn",
        "--script",
        "banner,ssl-cert,http-enum,fingerprint-strings",
        "-oX",
        str(NMAP_OUT),
    ] + hosts
    logger.info("nmap: %d hosts", len(hosts))
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
    except subprocess.TimeoutExpired:
        logger.warning("nmap 超時, 放棄指紋階段")
        return []
    except Exception as e:  # noqa: BLE001
        logger.warning("nmap 執行失敗: %s", e)
        return []
    return _parse_nmap_xml(NMAP_OUT)


def _parse_nmap_xml(path: Path) -> list[ServiceInfo]:
    """輕量解析 nmap XML 取 port/service/banner/ssl cert CN.

    不用 xml ElementTree 處理 namespace 麻煩, 直接正則抓 <port> 與 <script>.
    """
    out: list[ServiceInfo] = []
    if not path.exists():
        return out
    text = path.read_text(encoding="utf-8", errors="replace")
    # 每個 <host> 區塊
    for host_m in re.finditer(r"<host[^>]*>(.*?)</host>", text, re.S):
        host_body = host_m.group(1)
        addr_m = re.search(r'<address\s+addr="([^"]+)"', host_body)
        if not addr_m:
            continue
        host = addr_m.group(1)
        # 每個 <port>
        for port_m in re.finditer(
            r'<port\s+[^>]*portid="(\d+)"[^>]*>(.*?)</port>', host_body, re.S
        ):
            port = int(port_m.group(1))
            pbody = port_m.group(2)
            svc_m = re.search(
                r'<service\s+name="([^"]*)"(?:[^>]*product="([^"]*)")?', pbody
            )
            service = svc_m.group(1) if svc_m else None
            banner_parts: list[str] = []
            # banner script output
            for sm in re.finditer(r'<script\s+id="banner"[^>]*output="([^"]*)"', pbody):
                banner_parts.append(sm.group(1))
            for sm in re.finditer(
                r'<script\s+id="fingerprint-strings"[^>]*output="([^"]*)"', pbody
            ):
                banner_parts.append(sm.group(1))
            banner = " | ".join(banner_parts) or None
            # ssl-cert CN
            cn = None
            cn_m = re.search(r'ssl-cert.*?commonName=([^\s,"]+)', pbody, re.S)
            if cn_m:
                cn = cn_m.group(1)
            # http-enum title
            title = None
            t_m = re.search(r'http-enum.*?Title:\s*([^\s,"]+)', pbody, re.S)
            if t_m:
                title = t_m.group(1)
            out.append(
                ServiceInfo(
                    host=host,
                    port=port,
                    service=service,
                    banner=banner,
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
    uuid_re = re.compile(r'"uuid":"([^"]+)"')
    for line in GRAY_NODES.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or not line.startswith("vmess://"):
            continue
        # vmess:// 後為 base64 JSON
        try:
            payload = line[len("vmess://") :]
            obj = json.loads(
                base64.b64decode(payload).decode("utf-8", errors="replace")
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
) -> tuple[list[str], list[dict]]:
    """對配置不當服務用常見默認值重建 URI.

    Returns: (recovered_uris, leads)
    recovered_uris 標 recovered=True (寫 gray_nodes.jsonl 但 G3 審核才倒 resin)
    leads 含所有 host:port + 推測協議 (含未重建的)
    """
    recovered: list[str] = []
    leads: list[dict] = []
    ts = int(time.time())

    # 建立 host:port -> ServiceInfo 索引 (nmap 可能沒對所有 masscan open 結果跑)
    svc_map: dict[tuple[str, int], ServiceInfo] = {}
    for s in services:
        svc_map[(s.host, s.port)] = s

    seen: set[tuple[str, int, str]] = set()
    vmess_uuid_candidates = _load_existing_vmess_uuids() or [VMESS_DEFAULT_UUID]

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
            "recovered": False,
            "ts": ts,
        }

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
                key = (op.host, op.port, f"ss:{method}:{pwd}")
                if key in seen:
                    continue
                seen.add(key)
                uri = _build_ss_uri(op.host, op.port, method, pwd)
                cred_guess = True
                break

        elif proto == "trojan" and not has_real_domain:
            for pwd in TROJAN_DEFAULT_PASSWORDS:
                key = (op.host, op.port, f"trojan:{pwd}")
                if key in seen:
                    continue
                seen.add(key)
                uri = _build_trojan_uri(op.host, op.port, pwd)
                cred_guess = True
                break

        elif proto == "vmess" and not has_real_domain:
            # WS+TLS 配置不當: 用候選 UUID + 預設 path
            uid = vmess_uuid_candidates[0]
            for path in VMESS_DEFAULT_PATHS:
                key = (op.host, op.port, f"vmess:{uid}:{path}")
                if key in seen:
                    continue
                seen.add(key)
                uri = _build_vmess_uri(op.host, op.port, uid, path)
                cred_guess = True
                break

        if uri is not None:
            recovered.append(uri)
            lead["recovered"] = True
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
    existing["scan"] = summary
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
) -> dict:
    """執行完整掃描流程; 回傳 summary dict.

    Args:
        shards_file: 覆蓋 scan_shards.txt 路徑
        ports: 覆蓋 TCP ports
        rate: 覆蓋 masscan --rate
        enabled_override: 覆蓋 config 的 scan.enabled (主要給 CLI/--force 用)
    """
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    cfg = _load_scan_config()
    enabled = bool(enabled_override) if enabled_override is not None else cfg["enabled"]
    if not enabled:
        logger.info("scan.enabled=false, 不執行公網掃描 (預設安全態)")
        return {
            "scanned_ips": 0,
            "open_ports": 0,
            "services_identified": 0,
            "nodes_recovered": 0,
            "leads": 0,
            "reason": "disabled",
        }

    shards_path = shards_file or SHARDS_FILE
    targets = _load_shards(shards_path)
    if not targets:
        logger.info("no scan targets (%s 為空或全為註解)", shards_path)
        return {
            "scanned_ips": 0,
            "open_ports": 0,
            "services_identified": 0,
            "nodes_recovered": 0,
            "leads": 0,
            "reason": "no_targets",
        }

    use_ports = ports or cfg["ports_tcp"]
    use_rate = rate or cfg["rate"]

    logger.info(
        "掃描目標: %d 個 CIDR/IP, ports=%s, rate=%d", len(targets), use_ports, use_rate
    )

    open_ports = run_masscan(targets, use_ports, use_rate)
    logger.info("masscan 找到 %d 個 open host:port", len(open_ports))

    services = run_nmap(open_ports)
    logger.info("nmap 識別 %d 個服務條目", len(services))

    recovered_uris, leads = _reconstruct_nodes(services, open_ports)

    # 輸出
    _append_lines(GRAY_NODES, recovered_uris)
    _append_lines(LEADS_FILE, [json.dumps(l, ensure_ascii=False) for l in leads])

    summary = {
        "scanned_ips": len(targets),
        "open_ports": len(open_ports),
        "services_identified": len(services),
        "nodes_recovered": len(recovered_uris),
        "leads": len(leads),
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
