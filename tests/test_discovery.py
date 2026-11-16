from __future__ import annotations

import asyncio
import ipaddress

import pytest

from coldperimeter.consent import ConsentError, collect_consent
from coldperimeter.discovery import hosts
from coldperimeter.discovery.ports import parse_port_specs, scan_host


def test_parse_arp_table_macos_pads_short_octets():
    text = "? (192.168.1.20) at 0:b:2d:0:29:32 on en0 ifscope [ethernet]\n"
    assert hosts.parse_arp_table(text) == {"192.168.1.20": "00:0B:2D:00:29:32"}


def test_parse_arp_table_linux_and_windows():
    text = (
        "gateway (192.168.1.1) at a4:91:b1:aa:bb:cc [ether] on eth0\n"
        "  192.168.1.30          00-07-68-11-22-33     dynamic\n"
        "? (192.168.1.99) at (incomplete) on en0\n"
        "  192.168.1.255         ff-ff-ff-ff-ff-ff     static\n"
    )
    assert hosts.parse_arp_table(text) == {
        "192.168.1.1": "A4:91:B1:AA:BB:CC",
        "192.168.1.30": "00:07:68:11:22:33",
    }


def test_public_targets_are_refused():
    with pytest.raises(hosts.ScopeError):
        hosts.validate_targets(["8.8.8.8"])
    assert hosts.validate_targets(["192.168.1.5", "127.0.0.1"]) == ["192.168.1.5", "127.0.0.1"]


def test_public_and_oversized_networks_are_refused():
    with pytest.raises(hosts.ScopeError):
        hosts.validate_network(ipaddress.ip_network("8.8.8.0/24"))
    with pytest.raises(hosts.ScopeError):
        hosts.validate_network(ipaddress.ip_network("10.0.0.0/16"))
    hosts.validate_network(ipaddress.ip_network("10.0.0.0/16"), allow_large=True)
    hosts.validate_network(ipaddress.ip_network("192.168.1.0/24"))


def test_parse_port_specs():
    specs = parse_port_specs("80, modbus:1502,9999")
    assert [(s.port, s.role) for s in specs] == [(80, "http"), (1502, "modbus"), (9999, "unknown")]
    with pytest.raises(ValueError):
        parse_port_specs("bogus:80")
    with pytest.raises(ValueError):
        parse_port_specs("70000")


def test_scan_host_finds_only_listening_port(modbus_port):
    specs = parse_port_specs(f"modbus:{modbus_port},http:1")
    found = asyncio.run(scan_host("127.0.0.1", specs, delay=0, timeout=1))
    assert [(p.port, p.role) for p in found] == [(modbus_port, "modbus")]


def test_consent_is_mandatory():
    with pytest.raises(ConsentError):
        collect_consent("Store 12", None, "tech")
    consent = collect_consent("Store 12", "Owner", "tech")
    assert consent.site_name == "Store 12" and consent.recorded_at
