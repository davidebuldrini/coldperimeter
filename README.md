# ColdPerimeter

Read-only exposure audit for supermarket refrigeration controllers.

A maintenance technician plugs a laptop into the store network and runs one
command. ColdPerimeter:

1. finds refrigeration controllers on the local network (Danfoss system
   managers in this version);
2. works out whether, and how, they can be reached from the internet;
3. writes an intervention plan that isolates them without silencing
   temperature alarms.

It never changes anything: no passwords are tried, no settings are written,
nothing is configured on routers or controllers.

## Download

Ready-to-run builds for macOS and Windows are attached to each
[GitHub release](../../releases). They are **not code-signed**, so the
operating system warns on first launch:

- **macOS:** right-click `ColdPerimeter.app`, choose **Open**, then **Open**
  again in the dialog. If macOS still refuses, go to System Settings >
  Privacy & Security and click **Open Anyway**.
- **Windows:** in the "Windows protected your PC" window, click **More info**,
  then **Run anyway**. The interface uses Microsoft Edge WebView2, included in
  Windows 10 and 11; without it the interface opens in your browser.

Each release lists SHA-256 checksums so you can check the download.

## Graphical interface

```bash
.venv/bin/coldperimeter ui
```

A window opens and guides you through five steps: authorization, scope, scan,
on-site questions and results. From step 2 of the intervention plan, **Set up
the VPN** writes WireGuard configuration files and checks that the controller
answers through the tunnel. Reports and VPN files are saved under
`Documents/ColdPerimeter`.

Add `--browser` to use your web browser instead of a native window.

## Install from source

```bash
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -e '.[dev]'
```

## Use

```bash
.venv/bin/coldperimeter scan --site "Store 12" --authorized-by "Store owner" --operator "Your name"
```

The report is written to `out/report.html` (also `report.md` and `scan.json`).

Useful options:

| Option | Effect |
|---|---|
| `--network 192.168.10.0/24` | scan this network instead of the laptop's /24 |
| `--targets 192.168.10.20` | check only these addresses |
| `--probe-url https://probe.example` | test the public address from outside |
| `--offline` | make no request to the internet |
| `--checklist-file answers.yaml` | on-site answers from a file instead of prompts |
| `--lang it` | report in Italian |
| `--no-xml-probe` | skip the Danfoss `read_units` identity request |
| `--capture-dir captures` | also save raw device observations |

Rebuild a report from a saved scan, without touching the network:

```bash
.venv/bin/coldperimeter report out/scan.json --lang it
```

## What it sends on the network

- one ping per address, then a TCP connect to nine ports, one at a time per
  host with a pause in between;
- to web ports: one `GET /`, then one `read_units` request to `/xml.cgi`
  (a read command documented in the Danfoss XML interface guide), five
  seconds apart;
- to the router: UPnP read queries (WAN address and port-mapping list);
- to the internet, unless `--offline`: a public-address lookup, the public
  index lookup (Shodan InternetDB) and, if `--probe-url` is set, the probe
  request.

Scope is limited to private (RFC 1918) and loopback addresses, and a scan does
not start without a site name, an authorizer and an operator.

## VPN assistant (command line)

```bash
.venv/bin/coldperimeter vpn init --endpoint vpn.example.com --controller 192.168.10.20 --lang it
```

- `--topology direct` (default): the store dials the maintenance center, which
  needs a public address (a dynamic DNS name is fine).
- `--topology hub`: the center is behind carrier-grade NAT too, or you look
  after many stores. Stores and technicians both dial a small relay server;
  the relay lets technicians reach stores and blocks traffic between stores.
- `--store-device gateway` (default): a small Linux device next to the
  controller forwards only the listed controller ports.
  `--store-device router`: the store router runs WireGuard itself.
- `--server-public-key KEY`: add another store to a server you already set up.

The files are written to `vpn/` with an `INSTRUCTIONS.md`. They contain
private keys. Then, with the tunnel up:

```bash
.venv/bin/coldperimeter vpn verify --address 10.99.1.1 --port 80
```

## Probe server

`probe_server/` is a small service to deploy on a public host. It tests ports
only on the address the request comes from; the request has no target field.
Do not put it behind a reverse proxy: forwarded headers are not trusted.

```bash
.venv/bin/uvicorn probe_server.app:app --host 0.0.0.0 --port 8443
```

Set `COLDPERIMETER_PROBE_TOKEN` on both sides to require a shared token.

## Signatures

`coldperimeter/fingerprint/signatures/danfoss.yaml` holds the Danfoss
signatures. Entries marked `unverified` have not been confirmed on a real
unit. To refine them, collect raw observations on site:

```bash
.venv/bin/coldperimeter capture --targets 192.168.10.20 --site "Store 12" --authorized-by "Store owner" --operator "Your name"
```

Capture files and scan outputs contain customer network data. They stay on the
laptop and are git-ignored. Add `--sanitize` before sharing a capture.

## Tests

```bash
.venv/bin/python -m pytest
```

Simulated devices for manual trials:

```bash
.venv/bin/python -m tests.simulators.servers
```

## Known limits

- Recognition of real Danfoss controllers is not validated yet.
- The generated VPN files have not yet been tried on real routers and gateways.
- Firmware versions are shown, not compared with advisories automatically.
- Port forwards are read only when the router has UPnP enabled.
- No UDP checks (BACnet/IP), no other vendors.

## Licence

MIT. See [LICENSE](LICENSE), [SECURITY.md](SECURITY.md) and
[CONTRIBUTING.md](CONTRIBUTING.md).
