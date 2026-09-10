"""Ingestion + reconciliation pipeline.

ingest_observations : connector output -> host/service/dns rows + observation trail
reconcile           : recompute score + drive both state machines + emit events
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..models import (
    Source, Service, Observation, OwnershipSeed, EntityType,
    ExposureEvent, LifecycleHistory, ExposureState, utcnow,
)
from ..connectors.base import RawObservation
from . import correlation
from .confidence import Evidence, compute_score, ensure_aware
from .lifecycle import decide_exposure, auto_obsolete_transition

settings = get_settings()


# --------------------------------------------------------------------------- #
# Ingest
# --------------------------------------------------------------------------- #
def ingest_observations(db: Session, source: Source, obs_list: list[RawObservation]) -> int:
    seeds = list(db.scalars(select(OwnershipSeed)))
    count = 0
    for obs in obs_list:
        if obs.entity_kind == "service":
            if obs.ip is None or obs.port is None:
                continue
            host = correlation.upsert_host(db, obs.ip, obs.asn, obs.netblock)
            svc = correlation.upsert_service(db, host, obs, seeds)
            if obs.asserts_present:
                host.last_seen = obs.observed_at
                svc.last_seen = obs.observed_at
            db.add(Observation(
                source_id=source.id, entity_type=EntityType.service,
                entity_id=svc.id, service_id=svc.id,
                asserts_present=obs.asserts_present, raw_payload=obs.raw,
                observed_at=obs.observed_at,
            ))
            count += 1
        elif obs.entity_kind == "dns_name":
            if not obs.fqdn:
                continue
            dns = correlation.upsert_dns_name(db, obs, seeds)
            db.add(Observation(
                source_id=source.id, entity_type=EntityType.dns_name,
                entity_id=dns.id, asserts_present=obs.asserts_present,
                raw_payload=obs.raw, observed_at=obs.observed_at,
            ))
            count += 1
    db.flush()
    return count


# --------------------------------------------------------------------------- #
# Reconcile
# --------------------------------------------------------------------------- #
def _evidence_for(db: Session, service: Service) -> list[Evidence]:
    rows = db.execute(
        select(Observation, Source)
        .join(Source, Observation.source_id == Source.id)
        .where(Observation.service_id == service.id)
    ).all()
    ev: list[Evidence] = []
    for obs, src in rows:
        ev.append(Evidence(
            source_id=src.id, source_name=src.name, weight=src.weight,
            asserts_present=obs.asserts_present, observed_at=obs.observed_at,
            staleness_days=src.staleness_days,
        ))
    return ev


def _probe_confirms_absent(db: Session, service: Service, last_present_at) -> bool:
    row = db.execute(
        select(Observation, Source)
        .join(Source, Observation.source_id == Source.id)
        .where(Observation.service_id == service.id, Source.name == "nmap_probe")
        .order_by(Observation.observed_at.desc())
    ).first()
    if not row:
        return False
    obs, _ = row
    if obs.asserts_present:
        return False
    return last_present_at is None or ensure_aware(obs.observed_at) > ensure_aware(last_present_at)


def reconcile_service(db: Session, service: Service, now: datetime | None = None) -> list[ExposureEvent]:
    now = now or datetime.now(timezone.utc)
    ev = _evidence_for(db, service)
    result = compute_score(ev, now)

    # last time any source asserted present (fresh or not — it's a timestamp)
    present_times = [ensure_aware(e.observed_at) for e in ev if e.asserts_present]
    last_present_at = max(present_times) if present_times else None
    if last_present_at:
        service.last_present_at = last_present_at
    days_since = ((ensure_aware(now) - last_present_at).days if last_present_at else None)

    probe_absent = _probe_confirms_absent(db, service, last_present_at)

    decision = decide_exposure(
        current=service.exposure_state, score=result.score,
        threshold=settings.confirm_threshold, days_since_present=days_since,
        gone_after_days=settings.gone_after_days, probe_confirms_absent=probe_absent,
    )

    service.confidence_score = result.score
    emitted: list[ExposureEvent] = []

    if decision.state != service.exposure_state:
        service.exposure_state = decision.state
    if decision.event is not None:
        evt = ExposureEvent(
            service_id=service.id, type=decision.event, confidence_score=result.score,
        )
        db.add(evt)
        db.flush()
        emitted.append(evt)

    # governance side-effect: auto-obsolete
    new_lc = auto_obsolete_transition(service.lifecycle_status, service.exposure_state)
    if new_lc is not None:
        db.add(LifecycleHistory(
            service_id=service.id, from_status=service.lifecycle_status,
            to_status=new_lc, reason="auto_obsolete",
        ))
        service.lifecycle_status = new_lc

    return emitted


def reconcile_all(db: Session, now: datetime | None = None) -> list[ExposureEvent]:
    events: list[ExposureEvent] = []
    for svc in db.scalars(select(Service)):
        events.extend(reconcile_service(db, svc, now=now))
    db.flush()
    return events
