from __future__ import annotations

import os
import re
import stat

import pytest

from coldperimeter.cli import main
from coldperimeter.report.plan import load_locale
from coldperimeter.vpn import keys
from coldperimeter.vpn.output import save_plan
from coldperimeter.vpn.verify import verify_access
from coldperimeter.vpn.wireguard import VpnConfigError, VpnRequest, build_plan


def _parse(content: str) -> list[tuple[str, dict[str, list[str]]]]:
    """Split a WireGuard file into (section, {key: [values]}) blocks."""
    blocks: list[tuple[str, dict[str, list[str]]]] = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("["):
            blocks.append((line.strip("[]"), {}))
            continue
        key, _, value = line.partition("=")
        blocks[-1][1].setdefault(key.strip(), []).append(value.strip())
    return blocks


def _files(plan):
    return {f.role: _parse(f.content) for f in plan.files}


def _private_keys(plan) -> list[str]:
    found = []
    for f in plan.files:
        found += re.findall(r"PrivateKey = (\S+)", f.content)
    return found


def test_public_key_derives_from_private_key():
    pair = keys.generate_keypair()
    assert keys.is_valid_key(pair.private) and keys.is_valid_key(pair.public)
    assert keys.public_from_private(pair.private) == pair.public
    assert pair.private not in repr(pair)
    assert not keys.is_valid_key("not a key")


def test_direct_topology_files_match_each_other():
    plan = build_plan(
        VpnRequest(topology="direct", endpoint_host="vpn.example.com",
                   controller_ips=["192.168.10.20"], controller_ports=[80])
    )
    files = _files(plan)
    assert set(files) == {"server", "store"}
    (_, server_if), (_, server_peer) = files["server"]
    (_, store_if), (_, store_peer) = files["store"]

    assert keys.public_from_private(store_if["PrivateKey"][0]) == server_peer["PublicKey"][0]
    assert keys.public_from_private(server_if["PrivateKey"][0]) == store_peer["PublicKey"][0]
    assert store_peer["PresharedKey"] == server_peer["PresharedKey"]
    assert store_peer["Endpoint"] == ["vpn.example.com:51820"]
    assert store_peer["PersistentKeepalive"] == ["25"]
    # Gateway mode: the center only routes to the store's tunnel address.
    assert server_peer["AllowedIPs"] == ["10.99.1.1/32"]
    assert store_peer["AllowedIPs"] == ["10.99.0.1/32"]
    assert [(a.address, a.port) for a in plan.access] == [("10.99.1.1", 80)]


def test_gateway_forwards_only_listed_controller_ports():
    plan = build_plan(
        VpnRequest(topology="direct", endpoint_host="203.0.113.5",
                   controller_ips=["192.168.10.20", "192.168.10.21"], controller_ports=[80, 443])
    )
    store = next(f.content for f in plan.files if f.role == "store")
    dnat = re.findall(r"PostUp = iptables -t nat -A PREROUTING .*", store)
    assert len(dnat) == 4
    assert "--dport 80 -j DNAT --to-destination 192.168.10.20:80" in store
    assert "--dport 10443 -j DNAT --to-destination 192.168.10.21:443" in store
    assert "PostUp = iptables -A FORWARD -i %i -j DROP" in store
    # Every rule added on start is removed on stop.
    ups = re.findall(r"PostUp = iptables (.*)", store)
    downs = re.findall(r"PostDown = iptables (.*)", store)
    assert [re.sub(r"(^| )-A ", r"\1-D ", u, count=1) for u in ups] == downs


def test_router_mode_routes_only_the_controller():
    plan = build_plan(
        VpnRequest(topology="direct", endpoint_host="vpn.example.com",
                   controller_ips=["192.168.10.20"], store_device="router")
    )
    (_, _), (_, server_peer) = _files(plan)["server"]
    assert server_peer["AllowedIPs"] == ["10.99.1.1/32, 192.168.10.20/32"]
    store = next(f.content for f in plan.files if f.role == "store")
    assert "iptables" not in store


def test_hub_topology_blocks_store_to_store_traffic():
    plan = build_plan(
        VpnRequest(topology="hub", endpoint_host="hub.example.com",
                   controller_ips=["192.168.10.20"], store_number=7, technician_number=2)
    )
    files = _files(plan)
    assert set(files) == {"server", "store", "technician"}
    hub = next(f.content for f in plan.files if f.role == "server")
    rules = re.findall(r"PostUp = iptables -A FORWARD (.*)", hub)
    assert rules == [
        "-i %i -o %i -s 10.99.2.0/24 -j ACCEPT",
        "-i %i -o %i -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
        "-i %i -o %i -j DROP",
    ]
    (_, tech_if), (_, tech_peer) = files["technician"]
    assert tech_if["Address"] == ["10.99.2.2/32"]
    assert tech_peer["AllowedIPs"] == ["10.99.1.0/24"]
    (_, store_if), (_, store_peer) = files["store"]
    assert store_if["Address"] == ["10.99.1.7/32"]
    # The store answers technicians only, never other stores.
    assert store_peer["AllowedIPs"] == ["10.99.2.0/24"]
    peers = [block for name, block in files["server"] if name == "Peer"]
    assert sorted(p["AllowedIPs"][0] for p in peers) == ["10.99.1.7/32", "10.99.2.2/32"]


def test_existing_server_gets_only_a_peer_block():
    server = keys.generate_keypair()
    plan = build_plan(
        VpnRequest(topology="hub", endpoint_host="hub.example.com",
                   controller_ips=["192.168.10.20"], store_number=3,
                   server_public_key=server.public)
    )
    assert {f.role for f in plan.files} == {"store", "server-peer"}
    assert len(_private_keys(plan)) == 1  # the store's own key only
    store = _files(plan)["store"]
    assert store[1][1]["PublicKey"] == [server.public]


@pytest.mark.parametrize(
    "change",
    [
        {"topology": "mesh"},
        {"store_device": "nas"},
        {"endpoint_host": "bad host;rm"},
        {"controller_ips": []},
        {"controller_ips": ["8.8.8.8"]},
        {"controller_ports": [0]},
        {"store_number": 254},
        {"server_public_key": "nope"},
    ],
)
def test_invalid_requests_are_refused(change):
    base = dict(topology="direct", endpoint_host="vpn.example.com", controller_ips=["192.168.10.20"])
    with pytest.raises(VpnConfigError):
        build_plan(VpnRequest(**(base | change)))


@pytest.mark.parametrize("lang", ["en", "it"])
def test_saved_files_are_private_and_instructions_complete(tmp_path, lang):
    plan = build_plan(
        VpnRequest(topology="hub", endpoint_host="hub.example.com", controller_ips=["192.168.10.20"])
    )
    paths = save_plan(plan, tmp_path / "vpn", load_locale(lang)["vpn"])
    names = sorted(p.name for p in paths)
    assert names == ["INSTRUCTIONS.md", "hub.conf", "store-1.conf", "technician-1.conf"]
    for path in paths:
        if path.suffix == ".conf" and os.name == "posix":
            assert stat.S_IMODE(path.stat().st_mode) == 0o600
    instructions = (tmp_path / "vpn" / "INSTRUCTIONS.md").read_text(encoding="utf-8")
    assert "{" not in instructions
    for key in _private_keys(plan):
        assert key not in instructions


def test_vpn_init_command(tmp_path, capsys):
    out = tmp_path / "vpn"
    code = main([
        "vpn", "init", "--endpoint", "vpn.example.com",
        "--controller", "192.168.10.20", "--out", str(out), "--lang", "it",
    ])
    assert code == 0
    assert (out / "center.conf").exists() and (out / "store-1.conf").exists()
    printed = capsys.readouterr().out
    for key in re.findall(r"PrivateKey = (\S+)", (out / "center.conf").read_text()):
        assert key not in printed


def test_verify_reaches_simulated_controller(controller_port):
    result = verify_access("127.0.0.1", controller_port)
    assert result.reachable and result.title.startswith("Danfoss")
    assert not verify_access("127.0.0.1", 1).reachable
    with pytest.raises(Exception):
        verify_access("8.8.8.8", 80)
