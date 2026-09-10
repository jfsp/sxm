"""Seed the database from an inventory CSV.

Columns (header-matched, case-insensitive; falls back to positional order):
    IP, DNS name, Port number, Port type (TCP/UDP), Organisational unit responsible, Notes

Each row may carry any subset:
  * IP + port           -> host + service
  * IP + DNS            -> host + name resolving to it
  * DNS only            -> a name with nothing behind it (decommissioned/under-construction)
  * + Notes             -> analyst annotation on the service (service rows only)

Imported services are authoritative: attribution=owned, lifecycle=in_production, and
seeded via a 'manual_import' source (weight = confirm threshold) so they read as
'exposed' immediately. That evidence carries a staleness window (default 30d) — a grace
period during which real scanners are expected to corroborate; if none do, the service
ages out to not_observed/gone naturally. The import is silent (emits no appeared events).

Idempotent: safe to re-run. Re-running refreshes the manual evidence (extends the grace
window) and will not duplicate services, names, OUs, or identical notes.

Run inside the api container:
    docker compose exec api python -m app.import_csv /path/to/inventory.csv
    docker compose exec api python -m app.import_csv /path/to/inventory.csv --dry-run
"""
from __future__ import annotations

import argparse
import csv
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import get_settings
from .db import SessionLocal
from .models import (
    Host, DnsName, Service, OrgUnit, Source, SourceKind, Observation, EntityType,
    Annotation, LifecycleHistory, LifecycleStatus, ExposureState, Attribution,
    Protocol, User, utcnow,
)

settings = get_settings()
MANUAL_SOURCE = "manual_import"
LOGICAL = ("ip", "dns", "port", "ptype", "ou", "notes")


# --------------------------- CSV parsing --------------------------------- #
def _map_headers(header: list[str]) -> dict[str, int]:
    col: dict[str, int] = {}
    for idx, raw in enumerate(header):
        h = raw.strip().lower()
        if "dns" in h or ("name" in h and "unit" not in h):
            col.setdefault("dns", idx)
        elif "ip" in h:
            col.setdefault("ip", idx)
        elif ("port" in h and "type" in h) or "protocol" in h or h in ("type", "proto"):
            col.setdefault("ptype", idx)
        elif "port" in h:
            col.setdefault("port", idx)
        elif "unit" in h or "organ" in h or "responsible" in h or h == "ou":
            col.setdefault("ou", idx)
        elif "note" in h:
            col.setdefault("notes", idx)
    return col


def parse_rows(path: str) -> list[dict]:
    with open(path, newline="", encoding="utf-8-sig") as f:
        rows = list(csv.reader(f))
    if not rows:
        return []
    first = [c.strip().lower() for c in rows[0]]
    header_like = any(("ip" in c or "dns" in c or "port" in c) for c in first)
    if header_like:
        col = _map_headers(rows[0])
        data = rows[1:]
    else:
        col = {k: i for i, k in enumerate(LOGICAL)}
        data = rows
    out: list[dict] = []
    for r in data:
        if not any((c or "").strip() for c in r):
            continue
        def get(k: str) -> str:
            i = col.get(k)
            return r[i].strip() if (i is not None and i < len(r)) else ""
        out.append({k: get(k) for k in LOGICAL})
    return out


# --------------------------- summary ------------------------------------- #
@dataclass
class Summary:
    hosts_created: int = 0
    services_created: int = 0
    services_updated: int = 0
    dns_created: int = 0
    dns_nothing_behind: int = 0
    ou_created: int = 0
    annotations_added: int = 0
    notes_skipped_no_service: int = 0
    rows_skipped: int = 0
    warnings: list[str] = field(default_factory=list)

    def report(self) -> str:
        lines = [
            "import summary:",
            f"  hosts created         {self.hosts_created}",
            f"  services created      {self.services_created}",
            f"  services updated      {self.services_updated}",
            f"  dns names created     {self.dns_created}",
            f"  dns nothing-behind    {self.dns_nothing_behind}",
            f"  org units created     {self.ou_created}",
            f"  annotations added     {self.annotations_added}",
            f"  notes skipped (no svc){self.notes_skipped_no_service}",
            f"  rows skipped          {self.rows_skipped}",
        ]
        if self.warnings:
            lines.append(f"  warnings ({len(self.warnings)}):")
            lines += [f"    - {w}" for w in self.warnings[:20]]
            if len(self.warnings) > 20:
                lines.append(f"    … and {len(self.warnings) - 20} more")
        return "\n".join(lines)


# --------------------------- helpers ------------------------------------- #
def ensure_manual_source(db: Session, weight: int, staleness: int) -> Source:
    src = db.scalar(select(Source).where(Source.name == MANUAL_SOURCE))
    if src is None:
        src = Source(name=MANUAL_SOURCE, kind=SourceKind.pull_report, weight=weight,
                     cadence="on_demand", staleness_days=staleness, enabled=False)
        db.add(src)
        db.flush()
    else:
        src.weight, src.staleness_days = weight, staleness
    return src


def _get_or_create_host(db: Session, ip: str, s: Summary) -> Host:
    host = db.scalar(select(Host).where(Host.ip == ip))
    if host is None:
        host = Host(ip=ip)
        db.add(host)
        db.flush()
        s.hosts_created += 1
    else:
        host.last_seen = utcnow()
    return host


def _get_or_create_dns(db: Session, fqdn: str, host: Host | None, ip: str | None, s: Summary):
    dns = db.scalar(select(DnsName).where(DnsName.fqdn == fqdn))
    if dns is None:
        dns = DnsName(fqdn=fqdn, records={"A": [ip]} if ip else {},
                      resolves_to_host_id=host.id if host else None)
        db.add(dns)
        db.flush()
        s.dns_created += 1
        if host is None:
            s.dns_nothing_behind += 1
    else:
        dns.last_seen = utcnow()
        if host and dns.resolves_to_host_id is None:
            dns.resolves_to_host_id = host.id
        if ip:
            a = set((dns.records or {}).get("A", []))
            a.add(ip)
            dns.records = {**(dns.records or {}), "A": sorted(a)}
    return dns


def _get_or_create_ou(db: Session, name: str, cache: dict, s: Summary) -> OrgUnit:
    if name in cache:
        return cache[name]
    ou = db.scalar(select(OrgUnit).where(OrgUnit.name == name))
    if ou is None:
        ou = OrgUnit(name=name)
        db.add(ou)
        db.flush()
        s.ou_created += 1
    cache[name] = ou
    return ou


def _get_or_create_service(db: Session, host: Host, port: int, proto: Protocol, s: Summary):
    svc = db.scalar(select(Service).where(
        Service.host_id == host.id, Service.port == port, Service.protocol == proto))
    created = svc is None
    if created:
        svc = Service(host_id=host.id, port=port, protocol=proto)
        db.add(svc)
        db.flush()
        s.services_created += 1
    else:
        s.services_updated += 1
    return svc, created


def _refresh_manual_obs(db: Session, src: Source, svc: Service, row: dict, now):
    obs = db.scalar(select(Observation).where(
        Observation.source_id == src.id, Observation.service_id == svc.id))
    if obs is None:
        db.add(Observation(source_id=src.id, entity_type=EntityType.service, entity_id=svc.id,
                           service_id=svc.id, asserts_present=True, observed_at=now,
                           raw_payload={"import": True, "row": row}))
    else:
        obs.observed_at = now
        obs.asserts_present = True


def _add_annotation_once(db: Session, svc: Service, body: str, actor: int | None, s: Summary):
    exists = db.scalar(select(Annotation).where(
        Annotation.service_id == svc.id, Annotation.body == body))
    if exists is None:
        db.add(Annotation(service_id=svc.id, author_user_id=actor, body=body))
        s.annotations_added += 1


# --------------------------- import core --------------------------------- #
def import_rows(db: Session, rows: list[dict], *, actor_user_id: int | None,
                weight: int, staleness: int, dry_run: bool = False) -> Summary:
    s = Summary()
    src = ensure_manual_source(db, weight, staleness)
    now = utcnow()
    ou_cache: dict = {}
    confirmed = weight >= settings.confirm_threshold

    for i, row in enumerate(rows, start=1):
        ip = row["ip"] or None
        dns = row["dns"] or None
        if not ip and not dns:
            s.rows_skipped += 1
            s.warnings.append(f"row {i}: no IP and no DNS name")
            continue

        host = _get_or_create_host(db, ip, s) if ip else None
        if dns:
            _get_or_create_dns(db, dns, host, ip, s)
        ou = _get_or_create_ou(db, row["ou"], ou_cache, s) if row["ou"] else None

        svc = None
        if ip and row["port"]:
            try:
                port = int(row["port"])
            except ValueError:
                s.warnings.append(f"row {i}: invalid port '{row['port']}'")
                port = None
            if port is not None:
                proto = Protocol.udp if "udp" in row["ptype"].lower() else Protocol.tcp
                svc, _ = _get_or_create_service(db, host, port, proto, s)
                if svc.lifecycle_status != LifecycleStatus.in_production:
                    db.add(LifecycleHistory(
                        service_id=svc.id, from_status=svc.lifecycle_status,
                        to_status=LifecycleStatus.in_production, reason="manual_import",
                        actor_user_id=actor_user_id))
                    svc.lifecycle_status = LifecycleStatus.in_production
                svc.attribution = Attribution.owned
                if ou:
                    svc.org_unit_id = ou.id
                _refresh_manual_obs(db, src, svc, row, now)
                svc.confidence_score = max(svc.confidence_score, weight)
                svc.exposure_state = (ExposureState.exposed if confirmed
                                      else ExposureState.first_seen)
                svc.last_present_at = now
                svc.last_seen = now
        elif ip and row["ptype"] and not row["port"]:
            s.warnings.append(f"row {i}: port type without port number — no service created")

        if row["notes"]:
            if svc is not None:
                _add_annotation_once(db, svc, row["notes"], actor_user_id, s)
            else:
                s.notes_skipped_no_service += 1

    if dry_run:
        db.rollback()
    else:
        db.commit()
    return s


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Seed the SXM database from an inventory CSV.")
    ap.add_argument("path", help="path to the CSV file")
    ap.add_argument("--dry-run", action="store_true", help="parse and report without writing")
    ap.add_argument("--weight", type=int, default=settings.confirm_threshold,
                    help=f"manual_import evidence weight (default = T = {settings.confirm_threshold})")
    ap.add_argument("--staleness-days", type=int, default=30,
                    help="grace window before manual evidence stops counting (default 30)")
    args = ap.parse_args(argv)

    rows = parse_rows(args.path)
    if not rows:
        print("no data rows found")
        return 1
    with SessionLocal() as db:
        admin = db.scalar(select(User).where(User.username == settings.admin_username))
        s = import_rows(db, rows, actor_user_id=admin.id if admin else None,
                        weight=args.weight, staleness=args.staleness_days, dry_run=args.dry_run)
    print(("[dry-run] " if args.dry_run else "") + s.report())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
