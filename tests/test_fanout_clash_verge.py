from pathlib import Path

import yaml

from tools.sync_fanout_clash_verge import (
    MANAGED_GROUP,
    PROFILE_LINKS,
    PROFILE_UID,
    build_profile_plan,
    clash_proxy,
    replace_managed,
    usable_exits,
)


def exit_row(slot: int = 1, status: str = "up") -> dict:
    return {
        "slot": slot,
        "port": 22999 + slot,
        "region": "JP",
        "status": status,
        "exit_ip": "198.51.100.10",
        "socks_user": "fixture-user",
        "socks_pass": "fixture-pass",
    }


def test_usable_exits_requires_up_mapped_authenticated_slots() -> None:
    valid = exit_row()
    failed = exit_row(2, "failed")
    incomplete = exit_row(3)
    incomplete["socks_pass"] = ""

    assert usable_exits([failed, incomplete, valid]) == [valid]


def test_clash_proxy_is_stable_tcp_only_socks_bridge() -> None:
    proxy = clash_proxy(exit_row())

    assert proxy == {
        "name": "Fanout OpenVPN JP S01",
        "type": "socks5",
        "server": "127.0.0.1",
        "port": 23000,
        "username": "fixture-user",
        "password": "fixture-pass",
        "udp": False,
    }


def test_replace_managed_is_idempotent_and_preserves_other_entries() -> None:
    document = {
        "prepend": [{"name": "Fanout OpenVPN old", "type": "socks5"}],
        "append": [{"name": "keep", "type": "http"}],
        "delete": [],
    }
    addition = clash_proxy(exit_row())

    once = replace_managed(document, [addition])
    twice = replace_managed(once, [addition])

    assert once == twice
    assert once["prepend"] == []
    assert once["append"] == [{"name": "keep", "type": "http"}, addition]


def test_replace_managed_group_does_not_remove_similarly_named_proxy() -> None:
    document = {
        "prepend": [],
        "append": [
            {"name": MANAGED_GROUP, "type": "select", "proxies": ["old"]},
            {"name": "Fanout OpenVPN JP S01", "type": "select"},
        ],
        "delete": [],
    }
    group = {"name": MANAGED_GROUP, "type": "select", "proxies": ["new"]}

    updated = replace_managed(document, [group], group=True)

    assert updated["append"] == [
        {"name": "Fanout OpenVPN JP S01", "type": "select"},
        group,
    ]


def test_build_profile_plan_registers_dedicated_remote_profile(tmp_path: Path) -> None:
    profiles = tmp_path / "profiles"
    profiles.mkdir()
    (tmp_path / "profiles.yaml").write_text(
        yaml.safe_dump(
            {
                "current": "existing",
                "items": [
                    {
                        "uid": "existing",
                        "type": "remote",
                        "file": "existing.yaml",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    subscription = tmp_path / "clash.yaml"
    subscription.write_text(
        yaml.safe_dump({"proxies": [{"name": "remote", "type": "http"}]}),
        encoding="utf-8",
    )
    proxy = clash_proxy(exit_row())

    plan, aggregate_count = build_profile_plan(
        tmp_path,
        subscription.read_bytes(),
        "https://example.test/clash.yaml",
        [proxy],
    )

    profiles_document = yaml.safe_load(plan[tmp_path / "profiles.yaml"])
    by_uid = {item["uid"]: item for item in profiles_document["items"]}
    assert aggregate_count == 1
    assert profiles_document["current"] == PROFILE_UID
    assert by_uid[PROFILE_UID]["url"] == "https://example.test/clash.yaml"
    assert by_uid[PROFILE_UID]["option"]["proxies"] == PROFILE_LINKS["proxies"]
    proxy_document = yaml.safe_load(plan[profiles / f"{PROFILE_LINKS['proxies']}.yaml"])
    group_document = yaml.safe_load(plan[profiles / f"{PROFILE_LINKS['groups']}.yaml"])
    assert proxy_document["append"] == [proxy]
    assert group_document["append"][0]["proxies"] == [proxy["name"]]
