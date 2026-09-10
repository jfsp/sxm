from __future__ import annotations

import enum
from datetime import datetime, timezone

from sqlalchemy import (
    JSON, Boolean, DateTime, Enum, ForeignKey, Integer, String, Text,
    UniqueConstraint, func,
)
from sqlalchemy.dialects.postgresql import JSONB as _PG_JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base

# Portable JSON: real JSONB on PostgreSQL, generic JSON elsewhere (e.g. sqlite in tests).
JSONB = JSON().with_variant(_PG_JSONB(), "postgresql")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# --------------------------------------------------------------------------- #
# Enums
# --------------------------------------------------------------------------- #
class SourceKind(str, enum.Enum):
    push = "push"
    pull_rest = "pull_rest"
    pull_report = "pull_report"
    probe = "probe"


class SeedType(str, enum.Enum):
    ASN = "ASN"
    CIDR = "CIDR"
    Domain = "Domain"


class Protocol(str, enum.Enum):
    tcp = "tcp"
    udp = "udp"


class ExposureState(str, enum.Enum):
    first_seen = "first_seen"
    exposed = "exposed"
    not_observed = "not_observed"
    gone = "gone"


class LifecycleStatus(str, enum.Enum):
    new = "new"
    approved = "approved"
    in_production = "in_production"
    obsolete = "obsolete"
    removed = "removed"


class Attribution(str, enum.Enum):
    owned = "owned"
    candidate = "candidate"


class EntityType(str, enum.Enum):
    service = "service"
    dns_name = "dns_name"
    host = "host"


class ExposureEventType(str, enum.Enum):
    appeared = "appeared"
    disappeared = "disappeared"


class ChannelKind(str, enum.Enum):
    email = "email"
    telegram = "telegram"
    webhook = "webhook"
    console = "console"


class RoleName(str, enum.Enum):
    admin = "admin"
    analyst = "analyst"
    manager = "manager"


# --------------------------------------------------------------------------- #
# Identity / RBAC
# --------------------------------------------------------------------------- #
class Role(Base):
    __tablename__ = "role"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[RoleName] = mapped_column(Enum(RoleName), unique=True)
    permissions: Mapped[dict] = mapped_column(JSONB, default=dict)
    users: Mapped[list[User]] = relationship(back_populates="role")


class User(Base):
    __tablename__ = "user_account"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(150), unique=True, index=True)
    # null for OIDC-provisioned users (no local password)
    password_hash: Mapped[str | None] = mapped_column(String(255))
    email: Mapped[str | None] = mapped_column(String(255))
    oidc_sub: Mapped[str | None] = mapped_column(String(255), unique=True, index=True)
    role_id: Mapped[int] = mapped_column(ForeignKey("role.id"))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    role: Mapped[Role] = relationship(back_populates="users")


class AuditLog(Base):
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(primary_key=True)
    actor_user_id: Mapped[int | None] = mapped_column(ForeignKey("user_account.id"))
    action: Mapped[str] = mapped_column(String(120))
    target: Mapped[str] = mapped_column(String(255))
    before: Mapped[dict | None] = mapped_column(JSONB)
    after: Mapped[dict | None] = mapped_column(JSONB)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


# --------------------------------------------------------------------------- #
# Ownership / attribution
# --------------------------------------------------------------------------- #
class OrgUnit(Base):
    __tablename__ = "org_unit"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    parent_id: Mapped[int | None] = mapped_column(ForeignKey("org_unit.id"))
    parent: Mapped[OrgUnit | None] = relationship(remote_side="OrgUnit.id")


class OwnershipSeed(Base):
    __tablename__ = "ownership_seed"
    id: Mapped[int] = mapped_column(primary_key=True)
    type: Mapped[SeedType] = mapped_column(Enum(SeedType))
    value: Mapped[str] = mapped_column(String(255), index=True)
    org_unit_id: Mapped[int | None] = mapped_column(ForeignKey("org_unit.id"))


# --------------------------------------------------------------------------- #
# Sources
# --------------------------------------------------------------------------- #
class Source(Base):
    __tablename__ = "source"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(80), unique=True)
    kind: Mapped[SourceKind] = mapped_column(Enum(SourceKind))
    weight: Mapped[int] = mapped_column(Integer)
    cadence: Mapped[str] = mapped_column(String(40), default="on_demand")
    staleness_days: Mapped[int] = mapped_column(Integer, default=14)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    config_ref: Mapped[str | None] = mapped_column(String(255))


# --------------------------------------------------------------------------- #
# Assets
# --------------------------------------------------------------------------- #
class Host(Base):
    __tablename__ = "host"
    id: Mapped[int] = mapped_column(primary_key=True)
    ip: Mapped[str] = mapped_column(String(45), unique=True, index=True)
    asn: Mapped[str | None] = mapped_column(String(40))
    netblock: Mapped[str | None] = mapped_column(String(64))
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    services: Mapped[list[Service]] = relationship(back_populates="host")


class DnsName(Base):
    __tablename__ = "dns_name"
    id: Mapped[int] = mapped_column(primary_key=True)
    fqdn: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    records: Mapped[dict] = mapped_column(JSONB, default=dict)
    resolves_to_host_id: Mapped[int | None] = mapped_column(ForeignKey("host.id"))
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Service(Base):
    __tablename__ = "service"
    __table_args__ = (UniqueConstraint("host_id", "port", "protocol", name="uq_service_identity"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    host_id: Mapped[int] = mapped_column(ForeignKey("host.id"))
    port: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[Protocol] = mapped_column(Enum(Protocol))
    service_type: Mapped[str | None] = mapped_column(String(80))
    tls_info: Mapped[dict | None] = mapped_column(JSONB)
    confidence_score: Mapped[int] = mapped_column(Integer, default=0)
    exposure_state: Mapped[ExposureState] = mapped_column(
        Enum(ExposureState), default=ExposureState.first_seen
    )
    lifecycle_status: Mapped[LifecycleStatus] = mapped_column(
        Enum(LifecycleStatus), default=LifecycleStatus.new
    )
    attribution: Mapped[Attribution] = mapped_column(Enum(Attribution), default=Attribution.candidate)
    org_unit_id: Mapped[int | None] = mapped_column(ForeignKey("org_unit.id"))
    # last time ANY source asserted this service present (drives "absent >= N days")
    last_present_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    host: Mapped[Host] = relationship(back_populates="services")
    observations: Mapped[list[Observation]] = relationship(back_populates="service")
    annotations: Mapped[list[Annotation]] = relationship(back_populates="service")


class Observation(Base):
    __tablename__ = "observation"
    id: Mapped[int] = mapped_column(primary_key=True)
    source_id: Mapped[int] = mapped_column(ForeignKey("source.id"))
    entity_type: Mapped[EntityType] = mapped_column(Enum(EntityType))
    entity_id: Mapped[int] = mapped_column(Integer, index=True)
    asserts_present: Mapped[bool] = mapped_column(Boolean)
    raw_payload: Mapped[dict] = mapped_column(JSONB, default=dict)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)

    source: Mapped[Source] = relationship()
    # convenience relationship only valid when entity_type == service
    service_id: Mapped[int | None] = mapped_column(ForeignKey("service.id"))
    service: Mapped[Service | None] = relationship(back_populates="observations")


class Annotation(Base):
    __tablename__ = "annotation"
    id: Mapped[int] = mapped_column(primary_key=True)
    service_id: Mapped[int] = mapped_column(ForeignKey("service.id"))
    author_user_id: Mapped[int | None] = mapped_column(ForeignKey("user_account.id"))
    body: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    service: Mapped[Service] = relationship(back_populates="annotations")


class LifecycleHistory(Base):
    __tablename__ = "lifecycle_history"
    id: Mapped[int] = mapped_column(primary_key=True)
    service_id: Mapped[int] = mapped_column(ForeignKey("service.id"), index=True)
    from_status: Mapped[LifecycleStatus | None] = mapped_column(Enum(LifecycleStatus))
    to_status: Mapped[LifecycleStatus] = mapped_column(Enum(LifecycleStatus))
    reason: Mapped[str] = mapped_column(String(40))
    actor_user_id: Mapped[int | None] = mapped_column(ForeignKey("user_account.id"))
    changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ExposureEvent(Base):
    __tablename__ = "exposure_event"
    id: Mapped[int] = mapped_column(primary_key=True)
    service_id: Mapped[int] = mapped_column(ForeignKey("service.id"), index=True)
    type: Mapped[ExposureEventType] = mapped_column(Enum(ExposureEventType))
    confidence_score: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class SnapshotMetric(Base):
    __tablename__ = "snapshot_metric"
    id: Mapped[int] = mapped_column(primary_key=True)
    taken_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    granularity: Mapped[str] = mapped_column(String(10))  # weekly|daily
    org_unit_id: Mapped[int | None] = mapped_column(ForeignKey("org_unit.id"))
    metric_name: Mapped[str] = mapped_column(String(80))
    metric_value: Mapped[float] = mapped_column()


# --------------------------------------------------------------------------- #
# Alerting
# --------------------------------------------------------------------------- #
class AlertChannel(Base):
    __tablename__ = "alert_channel"
    id: Mapped[int] = mapped_column(primary_key=True)
    kind: Mapped[ChannelKind] = mapped_column(Enum(ChannelKind))
    config: Mapped[dict] = mapped_column(JSONB, default=dict)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)


class AlertRule(Base):
    __tablename__ = "alert_rule"
    id: Mapped[int] = mapped_column(primary_key=True)
    event_type: Mapped[ExposureEventType] = mapped_column(Enum(ExposureEventType))
    org_unit_scope: Mapped[int | None] = mapped_column(ForeignKey("org_unit.id"))
    channel_id: Mapped[int] = mapped_column(ForeignKey("alert_channel.id"))
    dedup_window_seconds: Mapped[int] = mapped_column(Integer, default=3600)
    throttle_seconds: Mapped[int] = mapped_column(Integer, default=0)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)


class AlertDelivery(Base):
    __tablename__ = "alert_delivery"
    id: Mapped[int] = mapped_column(primary_key=True)
    rule_id: Mapped[int] = mapped_column(ForeignKey("alert_rule.id"))
    event_ref: Mapped[int] = mapped_column(ForeignKey("exposure_event.id"))
    status: Mapped[str] = mapped_column(String(20))
    sent_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    error: Mapped[str | None] = mapped_column(Text)
