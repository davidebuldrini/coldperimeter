# Security policy

## Intended use

ColdPerimeter is a defensive, read-only audit tool. Use it only on networks
you own or have written permission to audit. Every scan records who
authorized it, and the scope is limited to private (RFC 1918) and loopback
addresses.

The tool never tries passwords, never writes to controllers, and never changes
router or firewall settings. The VPN assistant writes configuration files to
disk; a person applies them.

## What it sends on the network

| Target | What | When |
|---|---|---|
| Each address in scope | One ping, then TCP connect to nine ports, one at a time | Always |
| Devices with a web page | `GET /`, then one `read_units` request to `/xml.cgi`, five seconds apart | Unless disabled |
| Router | UPnP read queries (WAN address, port-mapping list) | Unless disabled |
| `api.ipify.org` | Public address lookup | Unless offline |
| `internetdb.shodan.io` | Lookup of the site's own public address | Unless offline |
| Your probe server | One request; the server tests the caller's own address | Only with a probe URL |

## Data handling

Scan results, reports, capture files and VPN files stay on the computer that
created them. VPN configuration files contain private keys and are written
with owner-only permissions. Nothing is uploaded and there is no telemetry.

The graphical interface runs a local server bound to `127.0.0.1` on a random
port. Every API call needs a random per-session token, the `Host` header is
checked against DNS rebinding, and no CORS headers are sent.

## Reporting a vulnerability

Report vulnerabilities in ColdPerimeter itself through GitHub's private
vulnerability reporting ("Report a vulnerability" on the repository's
Security tab). Please do not open a public issue.

Vulnerabilities in refrigeration controllers belong to their manufacturers'
disclosure programmes, not here.
