"""Connector registry — the single place new sources are wired in."""
from __future__ import annotations

from .base import Connector
from .impl import (
    TenableConnector, ShadowserverConnector, ShodanConnector, DnsdumpsterConnector,
    ElsaConnector, SocradarConnector, NmapProbeConnector,
)

CONNECTOR_CLASSES: dict[str, type[Connector]] = {
    c.name: c for c in (
        TenableConnector, ShadowserverConnector, ShodanConnector, DnsdumpsterConnector,
        ElsaConnector, SocradarConnector, NmapProbeConnector,
    )
}

# Pull sources eligible for the scheduled cycle (probe excluded — on trigger only, C9).
# ELSA/SOCRadar are registered but ship disabled; enable per deployment.
SCHEDULED_SOURCES = ["tenable", "shadowserver", "shodan", "dnsdumpster", "elsa", "socradar"]

# Which sources need discovery targets, and which seed type feeds them.
TARGET_SEED_TYPE = {"shodan": "CIDR", "dnsdumpster": "Domain"}


def build_connector(name: str, mode: str, config: dict | None = None) -> Connector:
    return CONNECTOR_CLASSES[name](mode=mode, config=config)
