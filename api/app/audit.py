from __future__ import annotations

from sqlalchemy.orm import Session

from .models import AuditLog, User


def record(db: Session, actor: User | None, action: str, target: str,
           before: dict | None = None, after: dict | None = None) -> None:
    db.add(AuditLog(
        actor_user_id=actor.id if actor else None,
        action=action, target=target, before=before, after=after,
    ))
