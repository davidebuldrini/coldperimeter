"""Fake Danfoss system manager, fake UPnP gateway and a bare TCP listener.

The Danfoss simulator answers ``read_units`` with the example response printed
in the vendor's XML interface guide. Its page title is an assumption, not a
capture from a real unit.

Run standalone:  python -m tests.simulators.servers
"""

from __future__ import annotations

import re
import socketserver
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DANFOSS_PAGE = (
    "<html><head><title>Danfoss StoreView Web - AK-SM 850A</title></head>"
    "<body><script src='xml.cgi'></script></body></html>"
)

READ_UNITS_RESPONSE = """<resp action="read_units" error="0">
  <total>1</total>
  <store_name>BIG FOOD STORE</store_name>
  <unit_name>AK-SM 850A Unit 0</unit_name>
  <storeId1>AREA0010</storeId1>
  <storeId2>STOR0125</storeId2>
  <memsize>32</memsize>
  <dateformat>0</dateformat>
  <software>S02.090</software>
  <macAddr>00-0B-2D-00-29-32</macAddr>
  <unit><addr>0</addr><ip>10.35.36.8</ip><port>80</port></unit>
  <unit_internet ><addr>0</addr><ip>93.184.216.34</ip><port>8081</port></unit_internet >
</resp>"""


class _Quiet(BaseHTTPRequestHandler):
    def log_message(self, *args) -> None:  # keep test output clean
        pass

    def _send(self, status: int, body: str, content_type: str = "text/html") -> None:
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)

    def _body(self) -> str:
        length = int(self.headers.get("Content-Length", "0"))
        return self.rfile.read(length).decode(errors="replace")


class DanfossHandler(_Quiet):
    server_version = "SM800A"

    def do_GET(self) -> None:
        self._send(200, DANFOSS_PAGE)

    def do_POST(self) -> None:
        body = self._body()
        if self.path == "/xml.cgi" and 'action="read_units"' in body:
            self._send(200, READ_UNITS_RESPONSE, "text/xml")
        else:
            self._send(404, "not found")


class PlainHandler(_Quiet):
    """A web device that is not a controller (e.g. a printer)."""

    def do_GET(self) -> None:
        self._send(200, "<html><head><title>Office printer</title></head></html>")

    def do_POST(self) -> None:
        self._send(404, "not found")


def make_igd_handler(mappings: list[dict], wan_ip: str):
    class IgdHandler(_Quiet):
        def do_GET(self) -> None:
            self._send(
                200,
                "<root><device><serviceList><service>"
                "<serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>"
                "<controlURL>/ctl</controlURL>"
                "</service></serviceList></device></root>",
                "text/xml",
            )

        def do_POST(self) -> None:
            body = self._body()
            action = self.headers.get("SOAPAction", "")
            if "GetExternalIPAddress" in action:
                self._send(200, f"<NewExternalIPAddress>{wan_ip}</NewExternalIPAddress>", "text/xml")
                return
            index = re.search(r"<NewPortMappingIndex>(\d+)</NewPortMappingIndex>", body)
            if "GetGenericPortMappingEntry" in action and index and int(index.group(1)) < len(mappings):
                m = mappings[int(index.group(1))]
                self._send(
                    200,
                    f"<NewExternalPort>{m['external_port']}</NewExternalPort>"
                    f"<NewProtocol>{m.get('protocol', 'TCP')}</NewProtocol>"
                    f"<NewInternalPort>{m['internal_port']}</NewInternalPort>"
                    f"<NewInternalClient>{m['internal_ip']}</NewInternalClient>"
                    f"<NewEnabled>1</NewEnabled>"
                    f"<NewPortMappingDescription>{m.get('description', '')}</NewPortMappingDescription>",
                    "text/xml",
                )
                return
            self._send(500, "<errorCode>713</errorCode>", "text/xml")

    return IgdHandler


class _Accept(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        pass


def start(server) -> int:
    """Serve in a daemon thread; return the bound port."""
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server.server_address[1]


def http_server(handler, port: int = 0) -> ThreadingHTTPServer:
    return ThreadingHTTPServer(("127.0.0.1", port), handler)


def tcp_listener(port: int = 0) -> socketserver.ThreadingTCPServer:
    return socketserver.ThreadingTCPServer(("127.0.0.1", port), _Accept)


if __name__ == "__main__":
    controller = http_server(DanfossHandler, 18080)
    modbus = tcp_listener(15020)
    gateway = http_server(
        make_igd_handler(
            [{"external_port": 8081, "internal_port": 18080, "internal_ip": "127.0.0.1",
              "description": "frigo"}],
            wan_ip="93.184.216.34",
        ),
        15000,
    )
    for srv in (controller, modbus, gateway):
        start(srv)
    print("controller http://127.0.0.1:18080  modbus 127.0.0.1:15020  "
          "gateway http://127.0.0.1:15000/desc.xml  (Ctrl+C to stop)")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass
