from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import require_admin
from ..models import Source, AlertChannel, AlertRule, User
from ..schemas import ChannelIn, ChannelOut, RuleIn, RuleOut, ProbeIn
from ..audit import record
from ..tasks import jobs

router = APIRouter(prefix="/api/admin", tags=["admin"])


# --- sources ------------------------------------------------------------- #
class SourceOut(BaseModel):
    id: int
    name: str
    weight: int
    enabled: bool
    cadence: str
    staleness_days: int

    class Config:
        from_attributes = True


class SourceUpdate(BaseModel):
    weight: int | None = None
    enabled: bool | None = None
    staleness_days: int | None = None


@router.get("/sources", response_model=list[SourceOut])
def list_sources(db: Session = Depends(get_db), _: User = Depends(require_admin)):
    return list(db.scalars(select(Source)))


@router.patch("/sources/{source_id}", response_model=SourceOut)
def update_source(source_id: int, body: SourceUpdate,
                  db: Session = Depends(get_db), user: User = Depends(require_admin)):
    src = db.get(Source, source_id)
    if not src:
        raise HTTPException(404, "source not found")
    before = {"weight": src.weight, "enabled": src.enabled, "staleness_days": src.staleness_days}
    if body.weight is not None:
        src.weight = body.weight
    if body.enabled is not None:
        src.enabled = body.enabled
    if body.staleness_days is not None:
        src.staleness_days = body.staleness_days
    record(db, user, "update_source", f"source:{src.id}", before=before,
           after={"weight": src.weight, "enabled": src.enabled})
    db.commit()
    db.refresh(src)
    return src


# --- alert channels / rules --------------------------------------------- #
@router.get("/alert-channels", response_model=list[ChannelOut])
def list_channels(db: Session = Depends(get_db), _: User = Depends(require_admin)):
    return list(db.scalars(select(AlertChannel)))


@router.post("/alert-channels", response_model=ChannelOut)
def create_channel(body: ChannelIn, db: Session = Depends(get_db),
                   user: User = Depends(require_admin)):
    ch = AlertChannel(kind=body.kind, config=body.config, enabled=body.enabled)
    db.add(ch)
    db.flush()
    record(db, user, "create_channel", f"channel:{ch.id}", after={"kind": ch.kind.value})
    db.commit()
    return ch


@router.get("/alert-rules", response_model=list[RuleOut])
def list_rules(db: Session = Depends(get_db), _: User = Depends(require_admin)):
    return list(db.scalars(select(AlertRule)))


@router.post("/alert-rules", response_model=RuleOut)
def create_rule(body: RuleIn, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    rule = AlertRule(
        event_type=body.event_type, channel_id=body.channel_id,
        org_unit_scope=body.org_unit_scope, dedup_window_seconds=body.dedup_window_seconds,
        throttle_seconds=body.throttle_seconds,
    )
    db.add(rule)
    db.flush()
    record(db, user, "create_rule", f"rule:{rule.id}", after={"event": body.event_type.value})
    db.commit()
    return rule


# --- probe (admin only, C9/RBAC) ---------------------------------------- #
@router.post("/probe")
def trigger_probe(body: ProbeIn, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    record(db, user, "probe", f"{body.ip}:{body.port}/{body.protocol.value}")
    db.commit()
    return jobs.run_probe(db, body.ip, body.port, body.protocol.value)


# --- run-now ops --------------------------------------------------------- #
@router.post("/run-cycle")
def run_cycle(db: Session = Depends(get_db), user: User = Depends(require_admin)):
    record(db, user, "run_cycle", "system")
    db.commit()
    return jobs.run_full_cycle(db)


@router.post("/snapshot")
def take_snapshot(granularity: str = "weekly", db: Session = Depends(get_db),
                  user: User = Depends(require_admin)):
    record(db, user, "snapshot", "system", after={"granularity": granularity})
    db.commit()
    return {"services_snapshotted": jobs.take_snapshot(db, granularity)}
