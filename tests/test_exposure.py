from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from coldperimeter import exposure
from coldperimeter.exposure import checklist, public_ip, upnp
from probe_server.app import create_app


def test_query_igd_reads_wan_address_and_mappings(gateway, controller_port):
    wan_ip, mappings = upnp.query_igd(gateway)
    assert wan_ip == "93.184.216.34"
    assert [(m.external_port, m.internal_ip, m.internal_port) for m in mappings] == [
        (8081, "127.0.0.1", controller_port),
        (3389, "192.168.1.50", 3389),
    ]


def test_igd_on_public_address_is_refused():
    with pytest.raises(upnp.UpnpError):
        upnp.query_igd("http://93.184.216.34/desc.xml")


def test_offline_assess_uses_router_only(gateway):
    result = exposure.assess(igd_url=gateway, offline=True)
    assert result.upnp_found and len(result.mappings) == 2
    assert not result.external_checked and result.public_ip is None
    assert result.behind_cgnat is False


def test_cgnat_detection():
    assert public_ip.behind_cgnat("100.64.3.7", "93.184.216.34") is True
    assert public_ip.behind_cgnat("192.168.0.2", None) is True
    assert public_ip.behind_cgnat("93.184.216.34", "93.184.216.34") is False
    assert public_ip.behind_cgnat("93.184.216.34", "93.184.216.99") is True
    assert public_ip.behind_cgnat(None, "93.184.216.34") is None


def test_checklist_file(tmp_path):
    path = tmp_path / "answers.yaml"
    path.write_text("cellular_router: yes\npasswords_changed: no\n")
    answers = checklist.load_answers(path)
    assert answers["cellular_router"] == "yes"
    assert answers["passwords_changed"] == "no"
    assert answers["dialup_modem"] == "unknown"
    path.write_text("made_up: yes\n")
    with pytest.raises(ValueError):
        checklist.load_answers(path)


# --- probe server -----------------------------------------------------------


def _client(app, host="127.0.0.1"):
    return TestClient(app, client=(host, 50000))


def test_probe_checks_only_the_caller(controller_port):
    app = create_app(allow_private=True, min_interval=0)
    answer = _client(app).post("/v1/probe", json={"ports": [controller_port, 1]}).json()
    assert answer["ip"] == "127.0.0.1"
    assert answer["ports"][str(controller_port)]["open"] is True
    assert answer["ports"][str(controller_port)]["title"].startswith("Danfoss")
    assert answer["ports"]["1"]["open"] is False


def test_probe_rejects_any_target_field():
    app = create_app(allow_private=True, min_interval=0)
    for field in ("target", "ip", "host"):
        response = _client(app).post("/v1/probe", json={"ports": [80], field: "8.8.8.8"})
        assert response.status_code == 422


def test_probe_refuses_private_callers_by_default():
    response = _client(create_app()).post("/v1/probe", json={"ports": [80]})
    assert response.status_code == 400


def test_probe_ignores_forwarded_headers(controller_port):
    app = create_app(allow_private=True, min_interval=0)
    answer = _client(app).post(
        "/v1/probe",
        json={"ports": [controller_port]},
        headers={"X-Forwarded-For": "8.8.8.8"},
    ).json()
    assert answer["ip"] == "127.0.0.1"


def test_probe_limits_ports_rate_and_token():
    app = create_app(allow_private=True, min_interval=60, token="secret")
    client = _client(app)
    assert client.post("/v1/probe", json={"ports": [1]}).status_code == 401
    auth = {"Authorization": "Bearer secret"}
    assert client.post("/v1/probe", json={"ports": list(range(1, 40))}, headers=auth).status_code == 422
    assert client.post("/v1/probe", json={"ports": [1]}, headers=auth).status_code == 200
    assert client.post("/v1/probe", json={"ports": [1]}, headers=auth).status_code == 429
