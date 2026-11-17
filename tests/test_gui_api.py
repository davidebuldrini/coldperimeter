from __future__ import annotations

import json
import time

import pytest
from fastapi.testclient import TestClient

from coldperimeter.fingerprint.capture import sanitize
from coldperimeter.gui.api import create_api
from tests.simulators.servers import READ_UNITS_RESPONSE

TOKEN = "test-token"
HOST = "127.0.0.1:5555"


@pytest.fixture
def opened():
    return []


@pytest.fixture
def client(tmp_path, opened):
    app = create_api(
        token=TOKEN,
        allowed_hosts={HOST},
        export_root=tmp_path / "exports",
        opener=opened.append,
    )
    with TestClient(app, base_url=f"http://{HOST}") as test_client:
        test_client.headers["X-ColdPerimeter-Token"] = TOKEN
        yield test_client


def _wait(client, job_id, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        snapshot = client.get(f"/api/scans/{job_id}").json()
        if snapshot["status"] != "running":
            return snapshot
        time.sleep(0.1)
    raise AssertionError("scan did not finish")


def _scan_body(controller_port, modbus_port, gateway, **extra):
    return {
        "site_name": "Test Store",
        "authorized_by": "Owner",
        "operator": "Tech",
        "confirmed": True,
        "targets": ["127.0.0.1"],
        "offline": True,
        "igd_url": gateway,
        "ports": f"http:{controller_port},modbus:{modbus_port}",
        "port_delay": 0,
        "request_gap": 0,
        **extra,
    }


# ---- guards ------------------------------------------------------------------


def test_missing_or_wrong_token_is_refused(client):
    assert client.get("/api/meta", headers={"X-ColdPerimeter-Token": ""}).status_code == 401
    assert client.get("/api/meta", headers={"X-ColdPerimeter-Token": "nope"}).status_code == 401
    assert client.get("/api/meta").status_code == 200


def test_foreign_host_header_is_refused(client):
    response = client.get("/api/meta", headers={"Host": "evil.example:5555"})
    assert response.status_code == 403
    assert client.get("/", headers={"Host": "evil.example:5555"}).status_code == 403


def test_no_cors_and_strict_headers(client):
    response = client.get("/api/meta", headers={"Origin": "http://evil.example"})
    assert "access-control-allow-origin" not in response.headers
    assert "default-src 'self'" in response.headers["content-security-policy"]


def test_static_page_needs_no_token_but_api_does(client):
    response = client.get("/", headers={"X-ColdPerimeter-Token": ""})
    assert response.status_code == 200 and "ColdPerimeter" in response.text


def test_locale_endpoint_rejects_unknown_language(client):
    assert "ui" in client.get("/api/locale/it").json()
    assert client.get("/api/locale/xx").status_code == 400


# ---- scan validation --------------------------------------------------------


def test_scan_needs_confirmed_authorization(client):
    body = {"site_name": "S", "authorized_by": "A", "operator": "O", "targets": ["127.0.0.1"]}
    assert client.post("/api/scans", json=body).status_code == 400
    body["confirmed"] = True
    body["operator"] = "  "
    assert client.post("/api/scans", json=body).status_code == 400


@pytest.mark.parametrize(
    "scope",
    [{"targets": ["8.8.8.8"]}, {"network": "8.8.8.0/24"}, {"network": "10.0.0.0/8"}],
)
def test_scan_refuses_out_of_scope_targets(client, scope):
    body = {"site_name": "S", "authorized_by": "A", "operator": "O", "confirmed": True, **scope}
    assert client.post("/api/scans", json=body).status_code == 400


def test_scan_rejects_unknown_fields(client):
    body = {"site_name": "S", "authorized_by": "A", "operator": "O", "confirmed": True,
            "targets": ["127.0.0.1"], "user": "admin", "password": "x"}
    assert client.post("/api/scans", json=body).status_code == 422


# ---- full flow ---------------------------------------------------------------


def test_full_scan_checklist_results_and_export(client, controller_port, modbus_port, gateway, opened):
    job_id = client.post("/api/scans", json=_scan_body(controller_port, modbus_port, gateway)).json()["id"]

    # Answers sent while the scan is still running are kept.
    assert client.post(
        f"/api/scans/{job_id}/checklist", json={"answers": {"cellular_router": "yes"}}
    ).status_code == 200

    snapshot = _wait(client, job_id)
    assert snapshot["status"] == "done"
    assert all(stage["status"] == "done" for stage in snapshot["stages"].values())

    result = client.get(f"/api/scans/{job_id}/result?lang=it").json()
    assert result["controllers"][0]["name"] == "Danfoss AK-SM 800A series"
    assert result["checklist"]["cellular_router"] == "yes"
    rule_ids = {f["rule_id"] for f in result["findings"]}
    assert {"UPNP-MAP-CONTROLLER", "XML-NOAUTH", "CHK-CELLULAR"} <= rule_ids
    assert [step["number"] for step in result["plan"]] == list(range(1, 8))
    assert result["plan"][1]["title"].startswith("Attivare la VPN")

    # Changing an answer afterwards re-applies the rules.
    client.post(f"/api/scans/{job_id}/checklist", json={"answers": {"cellular_router": "no"}})
    result = client.get(f"/api/scans/{job_id}/result").json()
    assert "CHK-CELLULAR" not in {f["rule_id"] for f in result["findings"]}

    response = client.post(f"/api/scans/{job_id}/open", json={"lang": "en", "what": "report"})
    assert response.status_code == 200
    assert opened and opened[-1].name == "report.html" and opened[-1].exists()
    assert (opened[-1].parent / "scan.json").exists()


def test_only_one_scan_at_a_time_and_cancel(client, controller_port, modbus_port, gateway):
    slow = _scan_body(controller_port, modbus_port, gateway, request_gap=30)
    first = client.post("/api/scans", json=slow).json()["id"]
    assert client.post("/api/scans", json=slow).status_code == 409
    client.post(f"/api/scans/{first}/cancel")
    assert _wait(client, first)["status"] == "cancelled"
    assert client.get(f"/api/scans/{first}/result").status_code == 409


def test_bad_checklist_answer_is_refused(client, controller_port, modbus_port, gateway):
    job_id = client.post("/api/scans", json=_scan_body(controller_port, modbus_port, gateway)).json()["id"]
    _wait(client, job_id)
    bad = client.post(f"/api/scans/{job_id}/checklist", json={"answers": {"cellular_router": "maybe"}})
    assert bad.status_code == 400
    unknown = client.post(f"/api/scans/{job_id}/checklist", json={"answers": {"made_up": "yes"}})
    assert unknown.status_code == 400


def test_import_saved_scan(client, controller_port, modbus_port, gateway, tmp_path):
    job_id = client.post("/api/scans", json=_scan_body(controller_port, modbus_port, gateway)).json()["id"]
    _wait(client, job_id)
    client.post(f"/api/scans/{job_id}/export", json={"lang": "en"})
    saved = next((tmp_path / "exports").glob("*/scan.json"))
    imported = client.post("/api/scans/import", json=json.loads(saved.read_text())).json()["id"]
    assert client.get(f"/api/scans/{imported}").json()["status"] == "done"
    assert client.get(f"/api/scans/{imported}/result").json()["consent"]["site_name"] == "Test Store"
    assert client.post("/api/scans/import", json={"hello": "world"}).status_code == 400


def test_unknown_scan_is_404(client):
    assert client.get("/api/scans/nope").status_code == 404


# ---- VPN ------------------------------------------------------------------------


def test_vpn_generate_writes_files_and_returns_no_private_key(client, tmp_path, opened):
    response = client.post("/api/vpn/generate", json={
        "site_name": "Test Store", "lang": "it", "topology": "hub",
        "endpoint_host": "hub.example.com", "controller_ips": ["192.168.10.20"],
    })
    assert response.status_code == 200
    data = response.json()
    assert {f["name"] for f in data["files"]} == {"hub.conf", "store-1.conf", "technician-1.conf"}
    folder = tmp_path / "exports" / data["dir"].rsplit("/", 1)[-1]
    for conf in folder.glob("*.conf"):
        for line in conf.read_text().splitlines():
            if line.startswith("PrivateKey"):
                assert line.split("=", 1)[1].strip() not in response.text

    assert client.post("/api/vpn/open", json={"dir": data["dir"]}).status_code == 200
    assert opened[-1] == folder.resolve()


def test_vpn_open_refuses_folders_outside_exports(client, tmp_path):
    assert client.post("/api/vpn/open", json={"dir": str(tmp_path)}).status_code == 400
    assert client.post("/api/vpn/open", json={"dir": "/"}).status_code == 400


def test_vpn_generate_rejects_bad_input(client):
    response = client.post("/api/vpn/generate", json={
        "endpoint_host": "hub.example.com", "controller_ips": ["8.8.8.8"],
    })
    assert response.status_code == 400


def test_vpn_verify(client, controller_port):
    ok = client.post("/api/vpn/verify", json={"address": "127.0.0.1", "port": controller_port}).json()
    assert ok["reachable"] is True
    assert client.post("/api/vpn/verify", json={"address": "8.8.8.8", "port": 80}).status_code == 400


# ---- capture sanitizer ---------------------------------------------------------


def test_sanitize_removes_store_identity_but_keeps_vendor_prefix():
    data = {
        "ip": "192.168.10.20",
        "mac": "00:0B:2D:12:34:56",
        "xml": {"store_name": "BIG FOOD STORE", "raw": READ_UNITS_RESPONSE},
        "http": [{"title": "Danfoss StoreView", "body_sample": "server 10.0.0.5"}],
    }
    clean = sanitize(data)
    text = json.dumps(clean)
    assert "BIG FOOD STORE" not in text and "STOR0125" not in text
    assert "192.168.10.20" not in text and "10.0.0.5" not in text and "93.184.216.34" not in text
    assert clean["mac"] == "00:0B:2D:00:00:00"
    assert "00-0B-2D-00-00-00" in clean["xml"]["raw"]
    assert clean["http"][0]["title"] == "Danfoss StoreView"
