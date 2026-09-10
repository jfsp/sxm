"""Idempotent bootstrap. Creates the schema (v1 uses create_all; Alembic is
scaffolded for future migrations) and seeds reference data."""
from __future__ import annotations

import logging

from sqlalchemy import select
from sqlalchemy.orm import Session

from .db import Base, engine, SessionLocal
from .config import get_settings
from .models import (
    Role, RoleName, User, Source, SourceKind, OwnershipSeed, SeedType,
    AlertChannel, AlertRule, ChannelKind, ExposureEventType,
)
from .security import hash_password

log = logging.getLogger("sxm.bootstrap")
settings = get_settings()

SOURCE_SEED = [
    # name, kind, weight, cadence, staleness_days, enabled
    ("tenable", SourceKind.pull_rest, 5, "weekly", 14, True),
    ("shadowserver", SourceKind.pull_report, 3, "daily", 3, True),
    ("shodan", SourceKind.pull_rest, 2, "poll", 10, True),
    ("dnsdumpster", SourceKind.pull_rest, 1, "enum", 30, True),
    ("nmap_probe", SourceKind.probe, 4, "on_demand", 3, True),
    # roadmap sources: registered but disabled until configured
    ("elsa", SourceKind.pull_rest, 3, "periodic", 14, False),
    ("socradar", SourceKind.pull_rest, 2, "periodic", 14, False),
]

OWNERSHIP_SEED = [
    (SeedType.CIDR, "198.51.100.0/24"),
    (SeedType.CIDR, "203.0.113.0/24"),
    (SeedType.ASN, "AS64500"),
    (SeedType.Domain, "example.org"),
]

ROLE_PERMS = {
    RoleName.admin: {"all": True},
    RoleName.analyst: {"triage": True, "annotate": True, "view": True},
    RoleName.manager: {"view": True},
}


def init_schema() -> None:
    Base.metadata.create_all(bind=engine)


def seed_roles(db: Session) -> dict[RoleName, Role]:
    out = {}
    for rn in RoleName:
        role = db.scalar(select(Role).where(Role.name == rn))
        if role is None:
            role = Role(name=rn, permissions=ROLE_PERMS[rn])
            db.add(role)
            db.flush()
        out[rn] = role
    return out


def ensure_admin(db: Session, roles: dict[RoleName, Role]) -> None:
    if db.scalar(select(User).where(User.username == settings.admin_username)):
        return
    db.add(User(
        username=settings.admin_username,
        password_hash=hash_password(settings.admin_password),
        role_id=roles[RoleName.admin].id,
    ))
    log.warning("Created bootstrap admin '%s' — change the password.", settings.admin_username)


def seed_sources(db: Session) -> None:
    for name, kind, weight, cadence, staleness, enabled in SOURCE_SEED:
        if db.scalar(select(Source).where(Source.name == name)):
            continue
        db.add(Source(name=name, kind=kind, weight=weight, cadence=cadence,
                      staleness_days=staleness, enabled=enabled))


def seed_ownership(db: Session) -> None:
    for stype, value in OWNERSHIP_SEED:
        if db.scalar(select(OwnershipSeed).where(OwnershipSeed.value == value)):
            continue
        db.add(OwnershipSeed(type=stype, value=value))


def seed_default_alerts(db: Session) -> None:
    if db.scalar(select(AlertChannel)):
        return
    ch = AlertChannel(kind=ChannelKind.console, config={}, enabled=True)
    db.add(ch)
    db.flush()
    for et in (ExposureEventType.appeared, ExposureEventType.disappeared):
        db.add(AlertRule(event_type=et, channel_id=ch.id, dedup_window_seconds=3600))


def bootstrap() -> None:
    init_schema()
    with SessionLocal() as db:
        roles = seed_roles(db)
        ensure_admin(db, roles)
        seed_sources(db)
        seed_ownership(db)
        seed_default_alerts(db)
        db.commit()
    log.info("Bootstrap complete.")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    bootstrap()
