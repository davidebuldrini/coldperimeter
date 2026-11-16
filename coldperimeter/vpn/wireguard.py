"""Build WireGuard configuration files for store, server and technician.

Address plan inside the tunnel (10.99.0.0/16):

* ``10.99.0.1``   the server: the maintenance center itself ("direct") or a
                  relay host with a public address ("hub");
* ``10.99.1.N``   store number N;
* ``10.99.2.N``   technician number N (hub topology only).

The store always dials out to the server, so the store needs no open port and
works behind carrier-grade NAT.

Store side, two modes:

* ``gateway``  a small dedicated Linux box next to the controller. It forwards
               only the listed TCP ports of the controller; the controller is
               reached at the store's tunnel address, so stores that all use
               the same LAN addresses never clash.
* ``router``   the store router terminates WireGuard itself. The controller is
               reached at its real LAN address, which is routed as a /32. That
               address must then be unique among the stores sharing a server.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

from .keys import KeyPair, generate_keypair, generate_preshared_key, is_valid_key

SERVER_ADDRESS = "10.99.0.1"
STORE_NET = "10.99.1.0/24"
TECH_NET = "10.99.2.0/24"
DEFAULT_PORT = 51820
KEEPALIVE = 25
# Extra controllers behind one gateway are published on shifted ports.
PORT_SHIFT = 10000

TOPOLOGIES = ("direct", "hub")
STORE_DEVICES = ("gateway", "router")

_HOSTNAME = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")


class VpnConfigError(ValueError):
    pass


@dataclass
class VpnRequest:
    topology: str
    endpoint_host: str
    controller_ips: list[str]
    controller_ports: list[int] = field(default_factory=lambda: [80, 443])
    store_device: str = "gateway"
    endpoint_port: int = DEFAULT_PORT
    store_number: int = 1
    technician_number: int = 1
    # Set when the server already exists: only the store side and a peer
    # block to append on the server are generated.
    server_public_key: str | None = None


@dataclass
class ConfigFile:
    name: str
    role: str  # "server" | "server-peer" | "store" | "technician"
    content: str


@dataclass
class Access:
    """How the maintenance side reaches one controller port."""

    controller_ip: str
    controller_port: int
    address: str
    port: int


@dataclass
class VpnPlan:
    request: VpnRequest
    files: list[ConfigFile]
    access: list[Access]
    public_keys: dict[str, str]


def _validate(request: VpnRequest) -> None:
    if request.topology not in TOPOLOGIES:
        raise VpnConfigError(f"Unknown topology: {request.topology}")
    if request.store_device not in STORE_DEVICES:
        raise VpnConfigError(f"Unknown store device: {request.store_device}")
    host = request.endpoint_host.strip()
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not _HOSTNAME.match(host):
            raise VpnConfigError("Server address must be a host name or an IP address.")
    if not 1 <= request.endpoint_port <= 65535:
        raise VpnConfigError("Server port out of range.")
    if not 1 <= request.store_number <= 253:
        raise VpnConfigError("Store number must be between 1 and 253.")
    if not 1 <= request.technician_number <= 253:
        raise VpnConfigError("Technician number must be between 1 and 253.")
    if not request.controller_ips:
        raise VpnConfigError("At least one controller address is needed.")
    for ip in request.controller_ips:
        try:
            address = ipaddress.ip_address(ip)
        except ValueError as exc:
            raise VpnConfigError(f"{ip!r} is not an IP address.") from exc
        if address.version != 4 or not address.is_private:
            raise VpnConfigError(f"{ip} is not a private IPv4 address.")
    if not request.controller_ports:
        raise VpnConfigError("At least one controller port is needed.")
    for port in request.controller_ports:
        if not 1 <= port <= 65535:
            raise VpnConfigError(f"Port out of range: {port}")
    if request.store_device == "gateway":
        top = max(request.controller_ports) + PORT_SHIFT * (len(request.controller_ips) - 1)
        if top > 65535:
            raise VpnConfigError("Too many controllers for one gateway.")
    if request.server_public_key and not is_valid_key(request.server_public_key):
        raise VpnConfigError("Server public key is not a valid WireGuard key.")


def _access(request: VpnRequest, store_address: str) -> list[Access]:
    entries = []
    for index, ip in enumerate(request.controller_ips):
        for port in request.controller_ports:
            if request.store_device == "gateway":
                entries.append(Access(ip, port, store_address, port + PORT_SHIFT * index))
            else:
                entries.append(Access(ip, port, ip, port))
    return entries


def _gateway_rules(access: list[Access]) -> list[str]:
    """wg-quick hooks: forward only the listed controller ports, drop the rest."""
    up = ["sysctl -w net.ipv4.ip_forward=1"]
    down = []
    for entry in access:
        target = f"{entry.controller_ip}:{entry.controller_port}"
        rules = [
            f"-t nat {{op}} PREROUTING -i %i -p tcp --dport {entry.port} "
            f"-j DNAT --to-destination {target}",
            f"{{op}} FORWARD -i %i -p tcp -d {entry.controller_ip} "
            f"--dport {entry.controller_port} -j ACCEPT",
            f"-t nat {{op}} POSTROUTING -p tcp -d {entry.controller_ip} "
            f"--dport {entry.controller_port} -j MASQUERADE",
        ]
        up += ["iptables " + r.format(op="-A") for r in rules]
        down += ["iptables " + r.format(op="-D") for r in rules]
    tail = [
        "{op} FORWARD -o %i -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
        "{op} FORWARD -i %i -j DROP",
    ]
    up += ["iptables " + r.format(op="-A") for r in tail]
    down += ["iptables " + r.format(op="-D") for r in tail]
    return [f"PostUp = {line}" for line in up] + [f"PostDown = {line}" for line in down]


def _hub_rules() -> list[str]:
    """Technicians may reach stores; stores can never reach each other."""
    rules = [
        f"{{op}} FORWARD -i %i -o %i -s {TECH_NET} -j ACCEPT",
        "{op} FORWARD -i %i -o %i -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
        "{op} FORWARD -i %i -o %i -j DROP",
    ]
    return (
        ["PostUp = sysctl -w net.ipv4.ip_forward=1"]
        + ["PostUp = iptables " + r.format(op="-A") for r in rules]
        + ["PostDown = iptables " + r.format(op="-D") for r in rules]
    )


def _block(header: str, lines: list[str]) -> str:
    return "\n".join([header, *lines])


def build_plan(request: VpnRequest) -> VpnPlan:
    """Generate keys and every configuration file for ``request``."""
    _validate(request)
    hub = request.topology == "hub"
    routed = request.store_device == "router"
    store_address = f"10.99.1.{request.store_number}"
    tech_address = f"10.99.2.{request.technician_number}"
    endpoint = f"{request.endpoint_host.strip()}:{request.endpoint_port}"
    controller_routes = [f"{ip}/32" for ip in request.controller_ips] if routed else []
    access = _access(request, store_address)

    store_keys = generate_keypair()
    store_psk = generate_preshared_key()
    server_keys: KeyPair | None = None
    if request.server_public_key:
        server_public = request.server_public_key
    else:
        server_keys = generate_keypair()
        server_public = server_keys.public

    files: list[ConfigFile] = []
    public_keys = {"server": server_public, "store": store_keys.public}

    # --- store ---------------------------------------------------------------
    store_interface = [f"Address = {store_address}/32", f"PrivateKey = {store_keys.private}"]
    if not routed:
        store_interface += _gateway_rules(access)
    # Replies go to whoever may call in: the technicians (hub) or the center.
    store_allowed = TECH_NET if hub else f"{SERVER_ADDRESS}/32"
    store_peer = [
        f"PublicKey = {server_public}",
        f"PresharedKey = {store_psk}",
        f"Endpoint = {endpoint}",
        f"AllowedIPs = {store_allowed}",
        f"PersistentKeepalive = {KEEPALIVE}",
    ]
    files.append(
        ConfigFile(
            name=f"store-{request.store_number}.conf",
            role="store",
            content=_block("[Interface]", store_interface)
            + "\n\n"
            + _block("[Peer]", store_peer)
            + "\n",
        )
    )

    # --- server peer block for this store -------------------------------------
    store_peer_on_server = _block(
        "[Peer]",
        [
            f"# store {request.store_number}",
            f"PublicKey = {store_keys.public}",
            f"PresharedKey = {store_psk}",
            "AllowedIPs = " + ", ".join([f"{store_address}/32", *controller_routes]),
        ],
    )

    server_name = "hub" if hub else "center"
    if server_keys is None:
        files.append(
            ConfigFile(
                name=f"{server_name}-add-store-{request.store_number}.conf",
                role="server-peer",
                content=store_peer_on_server + "\n",
            )
        )
        return VpnPlan(request, files, access, public_keys)

    server_interface = [
        f"Address = {SERVER_ADDRESS}/16",
        f"ListenPort = {request.endpoint_port}",
        f"PrivateKey = {server_keys.private}",
    ]
    server_blocks = [store_peer_on_server]

    if hub:
        server_interface += _hub_rules()
        tech_keys = generate_keypair()
        tech_psk = generate_preshared_key()
        public_keys["technician"] = tech_keys.public
        server_blocks.append(
            _block(
                "[Peer]",
                [
                    f"# technician {request.technician_number}",
                    f"PublicKey = {tech_keys.public}",
                    f"PresharedKey = {tech_psk}",
                    f"AllowedIPs = {tech_address}/32",
                ],
            )
        )
        files.append(
            ConfigFile(
                name=f"technician-{request.technician_number}.conf",
                role="technician",
                content=_block(
                    "[Interface]",
                    [f"Address = {tech_address}/32", f"PrivateKey = {tech_keys.private}"],
                )
                + "\n\n"
                + _block(
                    "[Peer]",
                    [
                        f"PublicKey = {server_public}",
                        f"PresharedKey = {tech_psk}",
                        f"Endpoint = {endpoint}",
                        "AllowedIPs = " + ", ".join([STORE_NET, *controller_routes]),
                        f"PersistentKeepalive = {KEEPALIVE}",
                    ],
                )
                + "\n",
            )
        )

    files.insert(
        0,
        ConfigFile(
            name=f"{server_name}.conf",
            role="server",
            content=_block("[Interface]", server_interface)
            + "\n\n"
            + "\n\n".join(server_blocks)
            + "\n",
        ),
    )
    return VpnPlan(request, files, access, public_keys)
