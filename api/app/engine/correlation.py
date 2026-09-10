"""Entity resolution + attribution (design doc section 5).

Maps normalized observations onto host / service / dns_name rows (identity key
for a service is (ip, port, protocol)) and decides owned vs candidate against
the ownership seeds.
"""
from __future__ import annotations

import ipaddress

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import (
    Host, Service, DnsName, OwnershipSeed, SeedType, Attribution, Protocol, utcnow,
)
from ..connectors.base import RawObservation


def attribute(ip: str | None, asn: str | None, fqdn: str | None,
              seeds: list[OwnershipSeed]) -> Attribution:
    """owned if IP in an owned CIDR, ASN owned, or FQDN under an owned apex."""
    for s in seeds:
        if s.type == SeedType.CIDR and ip:
            try:
                if ipaddress.ip_address(ip) in ipaddress.ip_network(s.value, strict=False):
                    return Attribution.owned
            except ValueError:
                pass
        elif s.type == SeedType.ASN and asn:
            if asn.replace("AS", "").strip() == s.value.replace("AS", "").strip():
                return Attribution.owned
        elif s.type == SeedType.Domain and fqdn:
            apex = s.value.lower().lstrip(".")
            if fqdn.lower() == apex or fqdn.lower().endswith("." + apex):
                return Attribution.owned
    return Attribution.candidate


def upsert_host(db: Session, ip: str, asn: str | None, netblock: str | None) -> Host:
    host = db.scalar(select(Host).where(Host.ip == ip))
    if host is None:
        host = Host(ip=ip, asn=asn, netblock=netblock)
        db.add(host)
        db.flush()
    else:
        host.last_seen = utcnow()
        if asn and not host.asn:
            host.asn = asn
        if netblock and not host.netblock:
            host.netblock = netblock
    return host


def upsert_service(db: Session, host: Host, obs: RawObservation,
                   seeds: list[OwnershipSeed]) -> Service:
    proto = Protocol(obs.protocol or "tcp")
    svc = db.scalar(
        select(Service).where(
            Service.host_id == host.id,
            Service.port == obs.port,
            Service.protocol == proto,
        )
    )
    if svc is None:
        svc = Service(
            host_id=host.id, port=obs.port, protocol=proto,
            service_type=obs.service_type,
            tls_info=obs.tls_info,
            attribution=attribute(obs.ip, obs.asn, None, seeds),
        )
        db.add(svc)
        db.flush()
    else:
        if obs.service_type and not svc.service_type:
            svc.service_type = obs.service_type
        if obs.tls_info:
            svc.tls_info = obs.tls_info
    return svc


def upsert_dns_name(db: Session, obs: RawObservation, seeds: list[OwnershipSeed]) -> DnsName:
    dns = db.scalar(select(DnsName).where(DnsName.fqdn == obs.fqdn))
    resolved_host = None
    if obs.resolves_to_ip:
        resolved_host = db.scalar(select(Host).where(Host.ip == obs.resolves_to_ip))
        if resolved_host is None:
            # discovery: surface the resolved IP as a host even if no scanner has a
            # service on it yet (off-range ones become candidates once a port is seen)
            resolved_host = upsert_host(db, obs.resolves_to_ip, obs.asn, obs.netblock)
    if dns is None:
        dns = DnsName(
            fqdn=obs.fqdn, records=obs.records or {},
            resolves_to_host_id=resolved_host.id if resolved_host else None,
        )
        db.add(dns)
        db.flush()
    else:
        dns.last_seen = utcnow()
        if obs.records:
            dns.records = obs.records
        if resolved_host:
            dns.resolves_to_host_id = resolved_host.id
    return dns
