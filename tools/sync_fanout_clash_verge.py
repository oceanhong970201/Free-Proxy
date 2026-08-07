"""Expose local Fanout OpenVPN exits to Clash Verge as SOCKS5 proxies."""

from __future__ import annotations

import argparse
import contextlib
import difflib
import hashlib
import http.cookiejar
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
from typing import Any
import urllib.parse
import urllib.request

import yaml


MANAGED_GROUP = "Fanout OpenVPN"
MANAGED_PREFIX = f"{MANAGED_GROUP} "
FANOUT_PORTS = range(23000, 23008)
SUBSCRIPTION_URL = (
    "https://raw.githubusercontent.com/oceanhong970201/Free-Proxy/"
    "master/output/clash.yaml"
)
PROFILE_UID = "FreeProxyF01"
PROFILE_NAME = "Free-Proxy + Fanout"
PROFILE_LINKS = {
    "merge": "FPMerge00001",
    "script": "FPScript0001",
    "rules": "FPRules00001",
    "proxies": "FPProxy00001",
    "groups": "FPGroups0001",
}


def default_verge_dir() -> Path:
    appdata = os.environ.get("APPDATA")
    if not appdata:
        raise RuntimeError("APPDATA is not set")
    return Path(appdata) / "io.github.clash-verge-rev.clash-verge-rev"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_yaml(path: Path) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise RuntimeError(f"expected a YAML mapping: {path}")
    return value


def dump_yaml(value: dict[str, Any]) -> bytes:
    return yaml.safe_dump(
        value, allow_unicode=True, sort_keys=False, default_flow_style=False
    ).encode("utf-8")


def atomic_write(path: Path, data: bytes) -> None:
    temporary = path.with_name(f".{path.name}.fanout.tmp")
    temporary.write_bytes(data)
    os.replace(temporary, path)


def docker_value(container: str, path: str) -> str:
    completed = subprocess.run(
        ["docker", "exec", container, "cat", path],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    value = completed.stdout.strip()
    if completed.returncode != 0 or not value:
        raise RuntimeError(f"Fanout runtime value is unavailable: {path}")
    return value


def fetch_exits(container: str, api_origin: str) -> list[dict[str, Any]]:
    base_path = docker_value(container, "/var/lib/fanout/basepath").strip("/")
    password = docker_value(container, "/var/lib/fanout/password")
    root = f"{api_origin.rstrip('/')}/{base_path}"
    cookies = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookies))
    login = urllib.request.Request(
        f"{root}/login",
        data=urllib.parse.urlencode({"password": password}).encode(),
        method="POST",
    )
    with opener.open(login, timeout=10):
        pass
    password = ""
    with opener.open(f"{root}/api/exits", timeout=10) as response:
        payload = json.load(response)
    exits = payload.get("exits", []) if isinstance(payload, dict) else []
    if not isinstance(exits, list):
        raise RuntimeError("Fanout returned an invalid exits document")
    return exits


def usable_exits(exits: list[dict[str, Any]]) -> list[dict[str, Any]]:
    usable: list[dict[str, Any]] = []
    for exit_row in exits:
        port = exit_row.get("port")
        if (
            exit_row.get("status") != "up"
            or not isinstance(port, int)
            or port not in FANOUT_PORTS
            or not str(exit_row.get("socks_user", "")).strip()
            or not str(exit_row.get("socks_pass", "")).strip()
        ):
            continue
        usable.append(exit_row)
    usable.sort(key=lambda row: int(row["slot"]))
    if not usable:
        raise RuntimeError("Fanout has no mapped up exit with complete credentials")
    return usable


def proxy_name(exit_row: dict[str, Any]) -> str:
    region = str(exit_row.get("region") or "XX").upper()
    return f"{MANAGED_PREFIX}{region} S{int(exit_row['slot']):02d}"


def clash_proxy(exit_row: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": proxy_name(exit_row),
        "type": "socks5",
        "server": "127.0.0.1",
        "port": int(exit_row["port"]),
        "username": str(exit_row["socks_user"]),
        "password": str(exit_row["socks_pass"]),
        "udp": False,
    }


def replace_managed(
    document: dict[str, Any], additions: list[dict[str, Any]], *, group: bool = False
) -> dict[str, Any]:
    result = dict(document)
    for key in ("prepend", "append", "delete"):
        if not isinstance(result.get(key), list):
            result[key] = []
    for key in ("prepend", "append"):
        result[key] = [
            item
            for item in result[key]
            if not (
                isinstance(item, dict)
                and isinstance(item.get("name"), str)
                and (
                    item["name"] == MANAGED_GROUP
                    if group
                    else item["name"].startswith(MANAGED_PREFIX)
                )
            )
        ]
    result["append"].extend(additions)
    return result


def build_profile_plan(
    verge_dir: Path,
    subscription_path: Path,
    subscription_url: str,
    proxies: list[dict[str, Any]],
) -> tuple[dict[Path, bytes], int]:
    profiles_path = verge_dir / "profiles.yaml"
    profiles_dir = verge_dir / "profiles"
    document = read_yaml(profiles_path)
    items = document.get("items")
    if not isinstance(items, list):
        raise RuntimeError("Clash Verge profiles.yaml has no items list")

    subscription = read_yaml(subscription_path)
    aggregate_proxies = subscription.get("proxies")
    if not isinstance(aggregate_proxies, list) or not aggregate_proxies:
        raise RuntimeError("Free-Proxy Clash subscription has no proxies")
    if any(not isinstance(proxy, dict) for proxy in aggregate_proxies):
        raise RuntimeError("Free-Proxy Clash subscription has an invalid proxy entry")

    by_uid = {
        item.get("uid"): item
        for item in items
        if isinstance(item, dict) and isinstance(item.get("uid"), str)
    }
    now = int(time.time())

    def upsert(uid: str, kind: str, filename: str) -> dict[str, Any]:
        item = by_uid.get(uid)
        if item is None:
            item = {"uid": uid}
            items.append(item)
            by_uid[uid] = item
        if item.get("type", kind) != kind:
            raise RuntimeError(f"Clash Verge UID {uid} is already used by another type")
        item.update(
            {"uid": uid, "type": kind, "name": None, "file": filename, "updated": now}
        )
        return item

    for kind, uid in PROFILE_LINKS.items():
        suffix = ".js" if kind == "script" else ".yaml"
        upsert(uid, kind, f"{uid}{suffix}")

    remote = upsert(PROFILE_UID, "remote", f"{PROFILE_UID}.yaml")
    option = remote.get("option")
    if not isinstance(option, dict):
        option = {}
    option.update(
        {
            "update_interval": 1440,
            "allow_auto_update": True,
            **PROFILE_LINKS,
        }
    )
    remote.update(
        {
            "name": PROFILE_NAME,
            "desc": (
                f"{len(aggregate_proxies)} verified Free-Proxy nodes plus "
                f"{len(proxies)} local Fanout exits"
            ),
            "url": subscription_url,
            "selected": remote.get("selected", []),
            "option": option,
        }
    )
    document["current"] = PROFILE_UID

    def yaml_or_empty(path: Path) -> dict[str, Any]:
        return read_yaml(path) if path.is_file() else {}

    proxy_path = profiles_dir / f"{PROFILE_LINKS['proxies']}.yaml"
    group_path = profiles_dir / f"{PROFILE_LINKS['groups']}.yaml"
    group = {
        "name": MANAGED_GROUP,
        "type": "select",
        "proxies": [proxy["name"] for proxy in proxies],
    }
    plan = {
        profiles_path: dump_yaml(document),
        profiles_dir / f"{PROFILE_UID}.yaml": subscription_path.read_bytes(),
        profiles_dir / f"{PROFILE_LINKS['merge']}.yaml": dump_yaml(
            {"profile": {"store-selected": True}}
        ),
        profiles_dir / f"{PROFILE_LINKS['script']}.js": (
            b"// Free-Proxy + Fanout profile script\n\n"
            b"function main(config, profileName) {\n  return config;\n}\n"
        ),
        profiles_dir / f"{PROFILE_LINKS['rules']}.yaml": dump_yaml(
            {"prepend": [], "append": [], "delete": []}
        ),
        proxy_path: dump_yaml(
            replace_managed(yaml_or_empty(proxy_path), proxies, group=False)
        ),
        group_path: dump_yaml(
            replace_managed(yaml_or_empty(group_path), [group], group=True)
        ),
    }
    return plan, len(aggregate_proxies)


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_for_port(port: int, process: subprocess.Popen[Any], timeout: float = 10) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("Mihomo exited before its local listener became ready")
        with contextlib.closing(socket.socket()) as probe:
            probe.settimeout(0.2)
            if probe.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.1)
    raise RuntimeError("Mihomo local listener startup timed out")


def curl_probe(arguments: list[str]) -> tuple[int, str]:
    completed = subprocess.run(
        ["curl.exe", *arguments],
        check=False,
        capture_output=True,
        text=True,
        timeout=25,
    )
    return completed.returncode, completed.stdout.strip()


def verify_bridge(
    core: Path,
    bridge_dir: Path,
    exits: list[dict[str, Any]],
    proxies: list[dict[str, Any]],
    aggregate_document: dict[str, Any],
) -> dict[str, Any]:
    baseline_results: list[dict[str, Any]] = []
    for exit_row in exits:
        code, output = curl_probe(
            [
                "-sS",
                "--fail",
                "--connect-timeout",
                "5",
                "--max-time",
                "20",
                "--proxy",
                f"socks5h://127.0.0.1:{exit_row['port']}",
                "--proxy-user",
                f"{exit_row['socks_user']}:{exit_row['socks_pass']}",
                "https://api.ipify.org",
            ]
        )
        expected = str(exit_row.get("exit_ip", ""))
        baseline_results.append(
            {
                "slot": int(exit_row["slot"]),
                "port": int(exit_row["port"]),
                "expected_ip": expected,
                "literal_output": output,
                "exit_status": code,
                "matches_fanout": code == 0 and output == expected,
            }
        )
    if not all(row["matches_fanout"] for row in baseline_results):
        raise RuntimeError("one or more direct Fanout SOCKS probes failed")

    mixed_port = free_port()
    controller_port = free_port()
    validation_path = bridge_dir / "mihomo-validation.yaml"
    aggregate_proxies = aggregate_document.get("proxies")
    if not isinstance(aggregate_proxies, list):
        raise RuntimeError("Free-Proxy validation document has no proxy list")
    validation = {
        "mixed-port": mixed_port,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "warning",
        "external-controller": f"127.0.0.1:{controller_port}",
        "proxies": [*aggregate_proxies, *proxies],
        "proxy-groups": [
            {
                "name": MANAGED_GROUP,
                "type": "select",
                "proxies": [proxy["name"] for proxy in proxies],
            }
        ],
        "rules": [f"MATCH,{MANAGED_GROUP}"],
    }
    atomic_write(validation_path, dump_yaml(validation))

    syntax_command = [str(core), "-t", "-d", str(bridge_dir), "-f", str(validation_path)]
    syntax = subprocess.run(
        syntax_command, check=False, capture_output=True, text=True, timeout=30
    )
    syntax_output = (syntax.stdout + syntax.stderr).strip()
    if syntax.returncode != 0:
        raise RuntimeError(f"Mihomo rejected the generated bridge: {syntax_output}")

    runtime_command = [str(core), "-d", str(bridge_dir), "-f", str(validation_path)]
    log_path = bridge_dir / "mihomo-validation.log"
    creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    with log_path.open("w", encoding="utf-8") as log:
        process = subprocess.Popen(
            runtime_command,
            stdout=log,
            stderr=subprocess.STDOUT,
            creationflags=creation_flags,
        )
        try:
            wait_for_port(mixed_port, process)
            wait_for_port(controller_port, process)
            modified_results: list[dict[str, Any]] = []
            for exit_row in exits:
                name = proxy_name(exit_row)
                selection = urllib.request.Request(
                    "http://127.0.0.1:"
                    f"{controller_port}/proxies/{urllib.parse.quote(MANAGED_GROUP, safe='')}",
                    data=json.dumps({"name": name}).encode(),
                    headers={"Content-Type": "application/json"},
                    method="PUT",
                )
                with urllib.request.urlopen(selection, timeout=5) as response:
                    selection_status = response.status
                code, output = curl_probe(
                    [
                        "-sS",
                        "--fail",
                        "--connect-timeout",
                        "5",
                        "--max-time",
                        "20",
                        "--proxy",
                        f"http://127.0.0.1:{mixed_port}",
                        "https://api.ipify.org",
                    ]
                )
                expected = str(exit_row.get("exit_ip", ""))
                modified_results.append(
                    {
                        "name": name,
                        "selection_http_status": selection_status,
                        "expected_ip": expected,
                        "literal_output": output,
                        "exit_status": code,
                        "matches_fanout": code == 0 and output == expected,
                    }
                )
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
    if not all(row["matches_fanout"] for row in modified_results):
        raise RuntimeError("one or more Mihomo-through-Fanout probes failed")

    return {
        "baseline": {
            "command": (
                "curl.exe -sS --fail --connect-timeout 5 --max-time 20 "
                "--proxy socks5h://127.0.0.1:PORT "
                "--proxy-user <Fanout-runtime-credential> https://api.ipify.org"
            ),
            "results": baseline_results,
        },
        "modified": {
            "syntax_command": subprocess.list2cmdline(syntax_command),
            "syntax_literal_output": syntax_output,
            "syntax_exit_status": syntax.returncode,
            "runtime_command": subprocess.list2cmdline(runtime_command),
            "probe_command": (
                f"curl.exe -sS --fail --connect-timeout 5 --max-time 20 "
                f"--proxy http://127.0.0.1:{mixed_port} https://api.ipify.org"
            ),
            "results": modified_results,
        },
    }


def make_rollback(
    backup_dir: Path, originals: dict[Path, bytes | None], bridge_dir: Path
) -> Path:
    rollback = bridge_dir / "rollback.ps1"
    lines = ["$ErrorActionPreference = 'Stop'"]
    ordered = sorted(originals, key=lambda path: path.name == "profiles.yaml")
    for target in ordered:
        if originals[target] is None:
            lines.append(
                f"if (Test-Path -LiteralPath '{target}') {{ "
                f"Remove-Item -LiteralPath '{target}' -Force }}"
            )
        else:
            source = backup_dir / target.name
            lines.append(
                f"Copy-Item -LiteralPath '{source}' -Destination '{target}' -Force"
            )
    lines.append("Write-Output 'Fanout Clash Verge enhancement rollback complete.'")
    atomic_write(rollback, ("\n".join(lines) + "\n").encode("utf-8"))
    return rollback


def apply_bridge(args: argparse.Namespace) -> int:
    verge_dir = args.verge_dir.resolve()
    exits = usable_exits(fetch_exits(args.container, args.api_origin))
    proxies = [clash_proxy(exit_row) for exit_row in exits]
    subscription_path = args.subscription_file.resolve()
    modified, aggregate_count = build_profile_plan(
        verge_dir, subscription_path, args.subscription_url, proxies
    )
    targets = list(modified)
    originals = {
        path: path.read_bytes() if path.is_file() else None for path in targets
    }

    stamp = time.strftime("%Y%m%d-%H%M%S")
    bridge_dir = verge_dir / "fanout-bridge"
    backup_dir = bridge_dir / "backups" / stamp
    backup_dir.mkdir(parents=True, exist_ok=False)
    for path, data in originals.items():
        if data is not None:
            (backup_dir / path.name).write_bytes(data)
    for path, data in modified.items():
        atomic_write(path, data)

    patch_parts: list[str] = []
    for path in targets:
        patch_parts.extend(
            difflib.unified_diff(
                (originals[path] or b"").decode("utf-8").splitlines(),
                modified[path].decode("utf-8").splitlines(),
                fromfile=f"original/{path.name}",
                tofile=f"modified/{path.name}",
                lineterm="",
            )
        )
    patch_path = bridge_dir / "last.patch"
    atomic_write(patch_path, ("\n".join(patch_parts) + "\n").encode("utf-8"))
    rollback_path = make_rollback(backup_dir, originals, bridge_dir)

    verification = verify_bridge(
        args.core.resolve(),
        bridge_dir,
        exits,
        proxies,
        read_yaml(subscription_path),
    )
    verification.update(
        {
            "generated_at": stamp,
            "node_count": len(proxies),
            "aggregate_node_count": aggregate_count,
            "combined_node_count": aggregate_count + len(proxies),
            "ports": [proxy["port"] for proxy in proxies],
            "artifacts": {
                "modified": [
                    {"path": str(path), "sha256": sha256(path.read_bytes())}
                    for path in targets
                ],
                "original": [
                    {
                        "target": str(path),
                        "backup": (
                            str(backup_dir / path.name)
                            if originals[path] is not None
                            else None
                        ),
                        "existed": originals[path] is not None,
                        "sha256": (
                            sha256(originals[path])
                            if originals[path] is not None
                            else None
                        ),
                    }
                    for path in targets
                ],
                "patch": str(patch_path),
                "rollback": str(rollback_path),
            },
        }
    )
    verification_path = bridge_dir / "verification.json"
    atomic_write(
        verification_path,
        (json.dumps(verification, ensure_ascii=True, indent=2) + "\n").encode(),
    )
    print(
        json.dumps(
            {
                "node_count": len(proxies),
                "aggregate_node_count": aggregate_count,
                "combined_node_count": aggregate_count + len(proxies),
                "ports": [proxy["port"] for proxy in proxies],
                "profile": PROFILE_NAME,
                "profile_uid": PROFILE_UID,
                "subscription_url": args.subscription_url,
                "verification": str(verification_path),
                "rollback": str(rollback_path),
            },
            indent=2,
        )
    )
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verge-dir", type=Path, default=default_verge_dir())
    parser.add_argument("--container", default="fanout-local")
    parser.add_argument("--api-origin", default="http://127.0.0.1:18899")
    parser.add_argument(
        "--subscription-file", type=Path, default=Path("output/clash.yaml")
    )
    parser.add_argument("--subscription-url", default=SUBSCRIPTION_URL)
    parser.add_argument(
        "--core",
        type=Path,
        default=Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
        / "Clash Verge"
        / "verge-mihomo.exe",
    )
    return parser.parse_args()


def main() -> int:
    try:
        return apply_bridge(parse_args())
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
