"""Lightweight DNS resolution for the discovery-expansion step (stdlib only).

Used in live mode to resolve enumerated subdomains that a source returned without
an A record, so off-range IPs surface as candidate hosts.
"""
from __future__ import annotations

import socket


def resolve_a(fqdn: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(fqdn, None, family=socket.AF_INET)
    except socket.gaierror:
        return []
    return sorted({i[4][0] for i in infos})
