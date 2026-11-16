from __future__ import annotations

import json
import re

import pytest

from coldperimeter.cli import main
from coldperimeter.exposure.checklist import QUESTIONS, unanswered
from coldperimeter.findings import rules
from coldperimeter.models import (
    DeviceMatch,
    Exposure,
    Host,
    OpenPort,
    PortMapping,
    ScanResult,
    XmlIdentity,
)
from coldperimeter.report.plan import available_languages, build_plan, load_locale


def _controller(ip="192.168.1.20") -> Host:
    return Host(
        ip=ip,
        open_ports=[OpenPort(80, "http"), OpenPort(502, "modbus"), OpenPort(23, "telnet")],
        xml=XmlIdentity(
            port=80, tls=False, responded=True, error_code="0",
            internet_addrs=[{"ip": "93.184.216.34", "port": "8081"}],
        ),
        device=DeviceMatch(
            vendor="Danfoss", family="AK", model_id="ak-sm-800a", model="AK-SM 800A series",
            firmware="S02.090", confidence="high", score=100,
            advisories=[{"id": "DSA-2023-08-01", "fixed_in": "3.3", "url": "https://example.invalid"}],
        ),
    )


def _ids(findings):
    return {f.rule_id for f in findings}


def _all_rule_ids() -> set[str]:
    source = open(rules.__file__, encoding="utf-8").read()
    return set(re.findall(r'"([A-Z]+(?:-[A-Z]+)+)"', source))


def test_exposed_controller_is_critical():
    exposure = Exposure(
        upnp_found=True, igd_url="http://192.168.1.1/desc.xml", wan_ip="93.184.216.34",
        public_ip="93.184.216.34", behind_cgnat=False, external_checked=True,
        mappings=[PortMapping(8081, "TCP", "192.168.1.20", 80)],
        external_ports={"8081": {"open": True, "title": "Danfoss"}, "22": {"open": True, "title": None}},
        index_checked=True, indexed_ports=[8081],
    )
    findings = rules.evaluate([_controller()], exposure, unanswered())
    by_id = {f.rule_id: f for f in findings}
    assert findings[0].severity == "critical"
    assert by_id["EXT-OPEN-CONTROLLER"].params["port"] == 8081
    assert by_id["EXT-OPEN-OTHER"].severity == "high"
    assert "UPNP-MAP-CONTROLLER" not in by_id  # not reported twice
    assert {"UPNP-ENABLED", "INDEXED", "XML-NOAUTH", "XML-PUBLIC-ADDR", "HTTP-PLAIN",
            "LEGACY-SVC", "MODBUS-OPEN", "ADVISORY", "FLAT-NET"} <= set(by_id)
    assert "EXT-NOT-TESTED" not in by_id


def test_mapping_without_external_test_is_critical_unless_cgnat():
    mapping = [PortMapping(8081, "TCP", "192.168.1.20", 80)]
    open_router = Exposure(upnp_found=True, mappings=mapping, behind_cgnat=False)
    nat = Exposure(upnp_found=True, mappings=mapping, behind_cgnat=True, wan_ip="100.64.1.2")
    sev = lambda e: next(  # noqa: E731
        f.severity for f in rules.evaluate([_controller()], e, unanswered())
        if f.rule_id == "UPNP-MAP-CONTROLLER"
    )
    assert sev(open_router) == "critical"
    assert sev(nat) == "medium"
    assert "EXT-NOT-TESTED" in _ids(rules.evaluate([_controller()], open_router, unanswered()))


def test_no_controller_and_checklist_rules():
    answers = unanswered() | {"cellular_router": "yes", "passwords_changed": "no",
                              "alarm_path_known": "yes"}
    unknown_modbus = Host(ip="192.168.1.77", open_ports=[OpenPort(502, "modbus")])
    ids = _ids(rules.evaluate([unknown_modbus], Exposure(), answers))
    assert {"NO-CONTROLLER", "UNIDENTIFIED", "CHK-CELLULAR", "CHK-PASSWORDS", "CHK-UNKNOWN"} <= ids
    assert "CHK-ALARM-PATH" not in ids


@pytest.mark.parametrize("lang", available_languages())
def test_every_rule_and_question_has_text(lang):
    locale = load_locale(lang)
    assert _all_rule_ids() <= set(locale["findings"])
    for texts in locale["findings"].values():
        assert set(texts) == {"title", "detail", "action"}
    assert set(QUESTIONS) <= set(locale["checklist"])
    assert set(locale["steps"]) == set(range(1, 8))


def test_locales_have_the_same_keys():
    en, it = load_locale("en"), load_locale("it")
    for section in ("labels", "severity", "confidence", "checklist", "findings"):
        assert set(en[section]) == set(it[section]), section
    assert len(en["limits"]) == len(it["limits"])


def test_plan_puts_vpn_and_alarm_check_before_closing_access():
    findings = rules.evaluate(
        [_controller()],
        Exposure(upnp_found=True, mappings=[PortMapping(8081, "TCP", "192.168.1.20", 80)]),
        unanswered(),
    )
    plan = build_plan(findings, load_locale("en"))
    assert [s.number for s in plan] == [1, 2, 3, 4, 5, 6, 7]
    assert "VPN" in plan[1].title and "alarms" in plan[2].title
    closing = [i.rule_id for i in plan[3].items]
    assert "UPNP-MAP-CONTROLLER" in closing
    assert all("{" not in i.action + i.detail + i.title for s in plan for i in s.items)


def test_end_to_end_scan_and_report(controller_port, modbus_port, gateway, tmp_path, capsys):
    out = tmp_path / "out"
    code = main([
        "scan", "--site", "Test Store", "--authorized-by", "Owner", "--operator", "Tech",
        "--targets", "127.0.0.1",
        "--ports", f"http:{controller_port},modbus:{modbus_port}",
        "--port-delay", "0", "--request-gap", "0",
        "--igd-url", gateway, "--offline", "--no-checklist",
        "--out", str(out),
    ])
    assert code == 0
    data = json.loads((out / "scan.json").read_text())
    ids = {f["rule_id"] for f in data["findings"]}
    assert {"UPNP-MAP-CONTROLLER", "UPNP-ENABLED", "XML-NOAUTH", "MODBUS-OPEN",
            "ADVISORY", "EXT-NOT-TESTED"} <= ids
    assert data["findings"][0]["severity"] == "critical"

    html = (out / "report.html").read_text()
    assert "Test Store" in html and "AK-SM 800A series" in html and "Owner" in html
    markdown = (out / "report.md").read_text()
    assert markdown.index("Bring up the VPN") < markdown.index("Remove direct access")

    # Rebuild in Italian from the saved scan, without touching the network.
    it_out = tmp_path / "it"
    assert main(["report", str(out / "scan.json"), "--lang", "it", "--out", str(it_out)]) == 0
    assert "Piano di intervento" in (it_out / "report.html").read_text()
    assert ScanResult.from_dict(data).to_dict() == data


def test_scan_refuses_public_targets_and_missing_consent(tmp_path, capsys):
    base = ["scan", "--no-checklist", "--offline", "--no-upnp", "--out", str(tmp_path)]
    consent = ["--site", "S", "--authorized-by", "A", "--operator", "O"]
    assert main(base + consent + ["--targets", "8.8.8.8"]) == 2
    assert main(base + ["--targets", "127.0.0.1"]) == 2
    assert not (tmp_path / "scan.json").exists()
