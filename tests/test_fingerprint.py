from __future__ import annotations

import asyncio
import json

from coldperimeter.discovery.ports import parse_port_specs
from coldperimeter.fingerprint import probe
from coldperimeter.fingerprint.engine import identify, load_signatures
from coldperimeter.models import Host, HttpObservation, OpenPort
from coldperimeter.scanner import ScanOptions, scan_local
from tests.simulators.servers import READ_UNITS_RESPONSE


def test_parse_read_units_from_vendor_example():
    ident = probe.parse_read_units(READ_UNITS_RESPONSE, 80, False)
    assert ident.responded and ident.error_code == "0"
    assert ident.store_name == "BIG FOOD STORE"
    assert ident.software == "S02.090"
    assert ident.mac == "00-0B-2D-00-29-32"
    assert ident.internet_addrs == [{"ip": "93.184.216.34", "port": "8081"}]


def test_non_xml_answer_is_not_a_response():
    assert not probe.parse_read_units("<html>404</html>", 80, False).responded


def test_mac_alone_is_only_a_low_confidence_candidate():
    host = Host(ip="192.168.1.20", mac="00:0B:2D:00:29:32")
    match = identify(host, load_signatures())
    assert match and match.confidence == "low" and match.model is None


def test_unrelated_web_device_is_not_identified():
    host = Host(
        ip="192.168.1.9",
        mac="A4:91:B1:AA:BB:CC",
        open_ports=[OpenPort(80, "http")],
        http=[HttpObservation(port=80, tls=False, status=200, title="Office printer")],
    )
    assert identify(host, load_signatures()) is None


def _scan(ports: str, **kwargs):
    options = ScanOptions(
        targets=["127.0.0.1"],
        port_specs=parse_port_specs(ports),
        port_delay=0,
        request_gap=0,
        **kwargs,
    )
    return asyncio.run(scan_local(options))[1][0]


def test_simulated_controller_is_identified(controller_port):
    host = _scan(f"http:{controller_port}")
    assert host.device is not None
    assert host.device.vendor == "Danfoss"
    assert host.device.model_id == "ak-sm-800a"
    assert host.device.confidence == "high"
    assert host.device.firmware == "S02.090"
    assert {a["id"] for a in host.device.advisories} >= {"DSA-2023-08-01"}


def test_printer_is_not_a_controller(printer_port):
    assert _scan(f"http:{printer_port}").device is None


def test_xml_probe_can_be_disabled(controller_port):
    host = _scan(f"http:{controller_port}", xml_probe=False)
    assert host.xml is None
    assert host.device is not None  # still recognised from the page


def test_capture_writes_raw_observations(controller_port, tmp_path):
    _scan(f"http:{controller_port}", capture_dir=tmp_path)
    data = json.loads((tmp_path / "127_0_0_1.json").read_text())
    assert data["http"][0]["title"].startswith("Danfoss")
