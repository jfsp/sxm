from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import select, func
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import require_viewer
from ..models import (
    Service, Host, DnsName, ExposureEvent, ExposureState, LifecycleStatus,
    Attribution, SnapshotMetric, LifecycleHistory, User,
)
from ..engine.pipeline import _evidence_for
from ..engine.confidence import compute_score

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


def _counts(db: Session, col, enum_cls):
    out = {e.value: 0 for e in enum_cls}
    rows = db.execute(select(col, func.count()).group_by(col)).all()
    for val, n in rows:
        out[val.value if hasattr(val, "value") else val] = n
    return out


@router.get("/summary")
def summary(db: Session = Depends(get_db), _: User = Depends(require_viewer)):
    total = db.scalar(select(func.count()).select_from(Service)) or 0
    dangling = db.scalar(
        select(func.count()).select_from(DnsName).where(DnsName.resolves_to_host_id.is_(None))
    ) or 0

    # coverage gaps (small estate; compute live)
    now = datetime.now(timezone.utc)
    gaps = []
    for svc in db.scalars(select(Service)):
        r = compute_score(_evidence_for(db, svc), now)
        if r.coverage_gap:
            host = db.get(Host, svc.host_id)
            gaps.append({
                "service_id": svc.id,
                "endpoint": f"{host.ip if host else '?'}:{svc.port}/{svc.protocol.value}",
                "score": r.score, "present_sources": r.present_sources,
            })

    return {
        "services_total": total,
        "by_exposure": _counts(db, Service.exposure_state, ExposureState),
        "by_lifecycle": _counts(db, Service.lifecycle_status, LifecycleStatus),
        "by_attribution": _counts(db, Service.attribution, Attribution),
        "dns_nothing_behind": dangling,
        "coverage_gaps": gaps,
    }


@router.get("/dns-dangling")
def dns_dangling(db: Session = Depends(get_db), _: User = Depends(require_viewer)):
    rows = db.scalars(select(DnsName).where(DnsName.resolves_to_host_id.is_(None)))
    return [{"id": d.id, "fqdn": d.fqdn, "records": d.records,
             "first_seen": d.first_seen} for d in rows]


@router.get("/events")
def recent_events(limit: int = 50, db: Session = Depends(get_db), _: User = Depends(require_viewer)):
    rows = db.scalars(
        select(ExposureEvent).order_by(ExposureEvent.created_at.desc()).limit(limit)
    )
    out = []
    for e in rows:
        svc = db.get(Service, e.service_id)
        host = db.get(Host, svc.host_id) if svc else None
        out.append({
            "type": e.type.value, "service_id": e.service_id,
            "endpoint": f"{host.ip if host else '?'}:{svc.port}/{svc.protocol.value}" if svc else "?",
            "confidence": e.confidence_score, "at": e.created_at,
        })
    return out


@router.get("/weekly-report")
def weekly_report(db: Session = Depends(get_db), _: User = Depends(require_viewer)):
    since = datetime.now(timezone.utc) - timedelta(days=7)
    appeared = db.scalar(
        select(func.count()).select_from(ExposureEvent)
        .where(ExposureEvent.type == "appeared", ExposureEvent.created_at >= since)
    ) or 0
    disappeared = db.scalar(
        select(func.count()).select_from(ExposureEvent)
        .where(ExposureEvent.type == "disappeared", ExposureEvent.created_at >= since)
    ) or 0
    transitions = db.scalar(
        select(func.count()).select_from(LifecycleHistory)
        .where(LifecycleHistory.changed_at >= since)
    ) or 0
    return {"window_days": 7, "appeared": appeared, "disappeared": disappeared,
            "lifecycle_transitions": transitions}


@router.get("/trends")
def trends(metric: str | None = None, granularity: str = "weekly",
           db: Session = Depends(get_db), _: User = Depends(require_viewer)):
    q = select(SnapshotMetric).where(SnapshotMetric.granularity == granularity)
    if metric:
        q = q.where(SnapshotMetric.metric_name == metric)
    series: dict[str, list] = defaultdict(list)
    for m in db.scalars(q.order_by(SnapshotMetric.taken_at)):
        series[m.metric_name].append({"at": m.taken_at, "value": m.metric_value})
    return series
