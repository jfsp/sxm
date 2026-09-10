"""Route exposure events to channels per rule, with dedup + throttle (C3, section 8)."""
from __future__ import annotations

from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import (
    AlertRule, AlertChannel, AlertDelivery, ExposureEvent, Service, Host, utcnow,
)
from . import channels


def _recent_delivery_exists(db: Session, rule: AlertRule, service_id: int, window_s: int) -> bool:
    """Dedup: same rule + same service already alerted within the window."""
    if window_s <= 0:
        return False
    cutoff = utcnow() - timedelta(seconds=window_s)
    q = (
        select(AlertDelivery)
        .join(ExposureEvent, AlertDelivery.event_ref == ExposureEvent.id)
        .where(
            AlertDelivery.rule_id == rule.id,
            ExposureEvent.service_id == service_id,
            AlertDelivery.sent_at >= cutoff,
            AlertDelivery.status == "sent",
        )
    )
    return db.scalar(q) is not None


def _throttled(db: Session, rule: AlertRule) -> bool:
    """Throttle: rate-limit ANY send for this rule (flap protection across services)."""
    if rule.throttle_seconds <= 0:
        return False
    cutoff = utcnow() - timedelta(seconds=rule.throttle_seconds)
    q = select(AlertDelivery).where(
        AlertDelivery.rule_id == rule.id,
        AlertDelivery.sent_at >= cutoff,
        AlertDelivery.status == "sent",
    )
    return db.scalar(q) is not None


def dispatch_event(db: Session, event: ExposureEvent) -> list[AlertDelivery]:
    svc = db.get(Service, event.service_id)
    host = db.get(Host, svc.host_id) if svc else None
    payload = {
        "event": event.type.value,
        "service_id": event.service_id,
        "endpoint": f"{host.ip if host else '?'}:{svc.port}/{svc.protocol.value}" if svc else "?",
        "service_type": svc.service_type if svc else None,
        "attribution": svc.attribution.value if svc else None,
        "confidence": event.confidence_score,
        "at": event.created_at.isoformat() if event.created_at else utcnow().isoformat(),
    }

    rules = db.scalars(
        select(AlertRule).where(
            AlertRule.event_type == event.type, AlertRule.enabled.is_(True)
        )
    ).all()

    deliveries: list[AlertDelivery] = []
    for rule in rules:
        if rule.org_unit_scope and svc and svc.org_unit_id != rule.org_unit_scope:
            continue
        if _recent_delivery_exists(db, rule, event.service_id, rule.dedup_window_seconds):
            continue
        if _throttled(db, rule):
            continue
        channel = db.get(AlertChannel, rule.channel_id)
        if not channel or not channel.enabled:
            continue
        d = AlertDelivery(rule_id=rule.id, event_ref=event.id, status="pending")
        try:
            channels.deliver(channel, payload)
            d.status = "sent"
        except Exception as exc:  # noqa: BLE001 - record and continue
            d.status = "failed"
            d.error = str(exc)[:500]
        db.add(d)
        deliveries.append(d)
    db.flush()
    return deliveries
