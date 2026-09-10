"""Orchestration jobs (session-in). Called by API 'run now' and Celery beat."""
from __future__ import annotations

from datetime import timedelta

from sqlalchemy import select, func, delete
from sqlalchemy.orm import Session

from ..config import get_settings
from ..models import (
    Source, Service, Host, DnsName, OwnershipSeed, SeedType, Observation,
    ExposureState, Attribution, SnapshotMetric, utcnow,
)
from ..connectors.registry import build_connector, SCHEDULED_SOURCES, TARGET_SEED_TYPE
from ..engine import pipeline
from ..alerting import router

settings = get_settings()


def _targets_for(db: Session, name: str) -> list[str]:
    stype = TARGET_SEED_TYPE.get(name)
    if not stype:
        return []
    return list(db.scalars(
        select(OwnershipSeed.value).where(OwnershipSeed.type == SeedType(stype))
    ))


def run_ingest_cycle(db: Session) -> dict:
    summary: dict[str, int] = {}
    for name in SCHEDULED_SOURCES:
        src = db.scalar(select(Source).where(Source.name == name))
        if src is None or not src.enabled:
            continue
        conn = build_connector(name, settings.connector_mode)
        try:
            obs = conn.fetch(targets=_targets_for(db, name))
        except NotImplementedError:
            continue  # source enabled but live impl not configured
        summary[name] = pipeline.ingest_observations(db, src, obs)
    db.commit()
    return summary


def run_reconcile(db: Session) -> dict:
    events = pipeline.reconcile_all(db)
    dispatched = 0
    for evt in events:
        dispatched += len(router.dispatch_event(db, evt))
    db.commit()
    return {"events": len(events), "deliveries": dispatched}


def _doubt_services(db: Session, limit: int) -> list[Service]:
    q = (
        select(Service).where(
            Service.attribution == Attribution.owned,            # candidates excluded (§13)
            Service.confidence_score > 0,
            Service.confidence_score < settings.confirm_threshold,
            Service.exposure_state.in_([ExposureState.first_seen, ExposureState.not_observed]),
        ).limit(limit)
    )
    return list(db.scalars(q))


def auto_probe_doubt(db: Session) -> dict:
    if not settings.auto_probe_on_doubt:
        return {"probed": 0}
    targets = _doubt_services(db, settings.auto_probe_max_per_cycle)
    src = db.scalar(select(Source).where(Source.name == "nmap_probe"))
    conn = build_connector("nmap_probe", settings.connector_mode)
    n = 0
    for svc in targets:
        host = db.get(Host, svc.host_id)
        if not host:
            continue
        obs = conn.fetch(ip=host.ip, port=svc.port, protocol=svc.protocol.value)
        pipeline.ingest_observations(db, src, obs)
        n += 1
    db.commit()
    if n:
        run_reconcile(db)
    return {"probed": n}


def run_full_cycle(db: Session) -> dict:
    ingest = run_ingest_cycle(db)
    recon = run_reconcile(db)
    probe = auto_probe_doubt(db)
    return {"ingested": ingest, **recon, **({"auto_probed": probe["probed"]} if probe["probed"] else {})}


def run_probe(db: Session, ip: str, port: int, protocol: str = "tcp") -> dict:
    src = db.scalar(select(Source).where(Source.name == "nmap_probe"))
    if src is None:
        raise ValueError("nmap_probe source not registered")
    conn = build_connector("nmap_probe", settings.connector_mode)
    obs = conn.fetch(ip=ip, port=port, protocol=protocol)
    pipeline.ingest_observations(db, src, obs)
    db.commit()
    events = pipeline.reconcile_all(db)
    for evt in events:
        router.dispatch_event(db, evt)
    db.commit()
    return {"probed": f"{ip}:{port}/{protocol}", "present": obs[0].asserts_present if obs else None}


def purge_observations(db: Session) -> int:
    """Retention: drop raw observation rows older than the window; derived state stays."""
    cutoff = utcnow() - timedelta(days=settings.observation_retention_days)
    res = db.execute(delete(Observation).where(Observation.observed_at < cutoff))
    db.commit()
    return res.rowcount or 0


def take_snapshot(db: Session, granularity: str = "weekly") -> int:
    def add(name: str, value: float):
        db.add(SnapshotMetric(granularity=granularity, metric_name=name, metric_value=value))

    total = db.scalar(select(func.count()).select_from(Service)) or 0
    add("services_total", total)
    for st in ExposureState:
        c = db.scalar(select(func.count()).select_from(Service).where(Service.exposure_state == st)) or 0
        add(f"exposure_{st.value}", c)
    for at in Attribution:
        c = db.scalar(select(func.count()).select_from(Service).where(Service.attribution == at)) or 0
        add(f"attribution_{at.value}", c)
    dangling = db.scalar(
        select(func.count()).select_from(DnsName).where(DnsName.resolves_to_host_id.is_(None))
    ) or 0
    add("dns_nothing_behind", dangling)
    db.commit()
    return int(total)
