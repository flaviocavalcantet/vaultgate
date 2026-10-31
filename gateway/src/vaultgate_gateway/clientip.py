"""The client's address, as access policies and logs see it (ADR 0004).

The same rules as the API's vaultgate_api.clientip; keep the two in step.

Behind a reverse proxy the TCP peer is the proxy, and `X-Forwarded-For` holds the
chain of addresses each proxy saw, with the nearest one appended last. Anyone can send
that header, so it counts only when the peer is a configured trusted proxy
(VAULTGATE_TRUSTED_PROXIES). The chain is then read from the right, skipping hops that
are themselves trusted proxies. The first address that is not one is the client. With
no trusted proxies configured, the header is ignored and the peer is the client.

Only proxy addresses belong in the trusted list, never networks that clients connect
from: a client inside a trusted range could write any address it likes into the header.

If the address cannot be determined (an unparseable hop reached through trusted
proxies, or a peer that is not an IP address), the result is None. Policies with
network conditions then refuse the request instead of falling back to the proxy's own
address, which may sit inside an allowed range.
"""

import ipaddress
from collections.abc import Iterable, Sequence

import tornado.httputil

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


def parse_ip(value: str) -> IPAddress:
    """An address, with IPv4-mapped IPv6 (::ffff:10.0.0.1) turned into plain IPv4, as
    dual-stack servers report IPv4 clients that way."""
    ip = ipaddress.ip_address(value.strip())
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def parse_networks(value: str | Iterable[str]) -> list[IPNetwork]:
    """Networks from a comma- or space-separated string (or a list): "10.0.0.0/8, ::1"."""
    items = value.replace(",", " ").split() if isinstance(value, str) else value
    return [ipaddress.ip_network(item.strip()) for item in items if item.strip()]


def _hop(value: str) -> IPAddress:
    """One X-Forwarded-For entry; some proxies add a port: "[2001:db8::1]:443", "1.2.3.4:80"."""
    value = value.strip()
    if value.startswith("["):
        value = value[1:].partition("]")[0]
    elif value.count(":") == 1:
        value = value.partition(":")[0]
    return parse_ip(value)


def resolve(
    peer: str | None, forwarded_for: Sequence[str], trusted: Sequence[IPNetwork]
) -> str | None:
    """The client address for a request from `peer` carrying these X-Forwarded-For
    header values (all of them, in order)."""
    try:
        address = parse_ip(peer) if peer else None
    except ValueError:
        return None
    if address is None:
        return None

    def is_trusted(ip: IPAddress) -> bool:
        return any(ip in network for network in trusted)

    if not forwarded_for or not is_trusted(address):
        return str(address)
    hops = [hop for value in forwarded_for for hop in value.split(",")]
    for hop in reversed(hops):
        try:
            address = _hop(hop)
        except ValueError:
            return None
        if not is_trusted(address):
            return str(address)
    # Every hop is a trusted proxy: the leftmost one is as far as the chain goes.
    return str(address)


def client_ip(
    request: tornado.httputil.HTTPServerRequest, trusted: Sequence[IPNetwork]
) -> str | None:
    """The client address of a Tornado request. Tornado's xheaders option stays off: it
    believes X-Forwarded-For from anyone."""
    return resolve(request.remote_ip, request.headers.get_list("X-Forwarded-For"), trusted)
