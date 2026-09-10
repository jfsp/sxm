from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict

from .models import (
    ExposureState, LifecycleStatus, Attribution, Protocol, SeedType,
    ExposureEventType, ChannelKind,
)


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# --- auth ---
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str


class UserOut(ORMModel):
    id: int
    username: str
    enabled: bool


# --- org / seeds ---
class OrgUnitIn(BaseModel):
    name: str
    parent_id: int | None = None


class OrgUnitOut(ORMModel):
    id: int
    name: str
    parent_id: int | None


class SeedIn(BaseModel):
    type: SeedType
    value: str
    org_unit_id: int | None = None


class SeedOut(ORMModel):
    id: int
    type: SeedType
    value: str
    org_unit_id: int | None


# --- services ---
class ServiceOut(ORMModel):
    id: int
    host_id: int
    port: int
    protocol: Protocol
    service_type: str | None
    confidence_score: int
    exposure_state: ExposureState
    lifecycle_status: LifecycleStatus
    attribution: Attribution
    org_unit_id: int | None
    last_present_at: datetime | None
    first_seen: datetime
    last_seen: datetime
    ip: str | None = None


class ServiceDetail(ServiceOut):
    ip: str | None = None
    coverage_gap: bool = False
    present_sources: list[str] = []


class LifecycleTransitionIn(BaseModel):
    to_status: LifecycleStatus


class OrgUnitAssignIn(BaseModel):
    org_unit_id: int | None = None


class AnnotationIn(BaseModel):
    body: str


class AnnotationOut(ORMModel):
    id: int
    body: str
    author_user_id: int | None
    created_at: datetime


# --- probe ---
class ProbeIn(BaseModel):
    ip: str
    port: int
    protocol: Protocol = Protocol.tcp


# --- alerts ---
class ChannelIn(BaseModel):
    kind: ChannelKind
    config: dict = {}
    enabled: bool = True


class ChannelOut(ORMModel):
    id: int
    kind: ChannelKind
    enabled: bool


class RuleIn(BaseModel):
    event_type: ExposureEventType
    channel_id: int
    org_unit_scope: int | None = None
    dedup_window_seconds: int = 3600
    throttle_seconds: int = 0


class RuleOut(ORMModel):
    id: int
    event_type: ExposureEventType
    channel_id: int
    org_unit_scope: int | None
    dedup_window_seconds: int
    enabled: bool


# --- user management ---
class UserCreate(BaseModel):
    username: str
    password: str
    role: str  # admin|analyst|manager


class UserUpdate(BaseModel):
    role: str | None = None
    enabled: bool | None = None
    password: str | None = None


class UserAdminOut(ORMModel):
    id: int
    username: str
    email: str | None
    enabled: bool
    oidc_sub: str | None
