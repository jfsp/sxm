from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import require_viewer, require_analyst
from ..models import (
    Service, Host, Annotation, LifecycleHistory, User,
    ExposureState, LifecycleStatus, Attribution,
)
from ..schemas import (
    ServiceOut, ServiceDetail, LifecycleTransitionIn, OrgUnitAssignIn,
    AnnotationIn, AnnotationOut,
)
from ..engine.pipeline import _evidence_for
from ..engine.confidence import compute_score
from ..engine.lifecycle import is_manual_transition_allowed
from ..audit import record

router = APIRouter(prefix="/api/services", tags=["services"])


@router.get("", response_model=list[ServiceOut])
def list_services(
    db: Session = Depends(get_db), _: User = Depends(require_viewer),
    exposure: ExposureState | None = None,
    lifecycle: LifecycleStatus | None = None,
    attribution: Attribution | None = None,
    org_unit_id: int | None = None,
    limit: int = Query(500, le=2000),
):
    q = select(Service)
    if exposure:
        q = q.where(Service.exposure_state == exposure)
    if lifecycle:
        q = q.where(Service.lifecycle_status == lifecycle)
    if attribution:
        q = q.where(Service.attribution == attribution)
    if org_unit_id:
        q = q.where(Service.org_unit_id == org_unit_id)
    services = list(db.scalars(q.order_by(Service.confidence_score.desc()).limit(limit)))
    hosts = {}
    if services:
        ids = {s.host_id for s in services}
        hosts = {h.id: h.ip for h in db.scalars(select(Host).where(Host.id.in_(ids)))}
    out = []
    for s in services:
        o = ServiceOut.model_validate(s)
        o.ip = hosts.get(s.host_id)
        out.append(o)
    return out


@router.get("/{service_id}", response_model=ServiceDetail)
def get_service(service_id: int, db: Session = Depends(get_db), _: User = Depends(require_viewer)):
    svc = db.get(Service, service_id)
    if not svc:
        raise HTTPException(404, "service not found")
    host = db.get(Host, svc.host_id)
    result = compute_score(_evidence_for(db, svc), datetime.now(timezone.utc))
    detail = ServiceDetail.model_validate(svc)
    detail.ip = host.ip if host else None
    detail.coverage_gap = result.coverage_gap
    detail.present_sources = result.present_sources
    return detail


@router.post("/{service_id}/lifecycle", response_model=ServiceOut)
def transition_lifecycle(service_id: int, body: LifecycleTransitionIn,
                         db: Session = Depends(get_db), user: User = Depends(require_analyst)):
    svc = db.get(Service, service_id)
    if not svc:
        raise HTTPException(404, "service not found")
    if not is_manual_transition_allowed(svc.lifecycle_status, body.to_status):
        raise HTTPException(
            409, f"transition {svc.lifecycle_status.value} -> {body.to_status.value} not allowed",
        )
    old = svc.lifecycle_status
    db.add(LifecycleHistory(
        service_id=svc.id, from_status=old, to_status=body.to_status,
        reason="manual", actor_user_id=user.id,
    ))
    svc.lifecycle_status = body.to_status
    record(db, user, "lifecycle_transition", f"service:{svc.id}",
           before={"status": old.value}, after={"status": body.to_status.value})
    db.commit()
    db.refresh(svc)
    return svc


@router.post("/{service_id}/org-unit", response_model=ServiceOut)
def assign_org_unit(service_id: int, body: OrgUnitAssignIn,
                    db: Session = Depends(get_db), user: User = Depends(require_analyst)):
    svc = db.get(Service, service_id)
    if not svc:
        raise HTTPException(404, "service not found")
    before = svc.org_unit_id
    svc.org_unit_id = body.org_unit_id
    record(db, user, "assign_org_unit", f"service:{svc.id}",
           before={"org_unit_id": before}, after={"org_unit_id": body.org_unit_id})
    db.commit()
    db.refresh(svc)
    return svc


@router.get("/{service_id}/annotations", response_model=list[AnnotationOut])
def list_annotations(service_id: int, db: Session = Depends(get_db), _: User = Depends(require_viewer)):
    return list(db.scalars(select(Annotation).where(Annotation.service_id == service_id)))


@router.post("/{service_id}/annotations", response_model=AnnotationOut)
def add_annotation(service_id: int, body: AnnotationIn,
                   db: Session = Depends(get_db), user: User = Depends(require_analyst)):
    if not db.get(Service, service_id):
        raise HTTPException(404, "service not found")
    ann = Annotation(service_id=service_id, author_user_id=user.id, body=body.body)
    db.add(ann)
    db.commit()
    db.refresh(ann)
    return ann
