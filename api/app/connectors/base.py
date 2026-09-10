"""Pluggable connector interface.

Every source — Tenable, Shadowserver, Shodan, dnsdumpster, nmap probe, and future
ELSA/SOCRadar — implements ``fetch()`` and returns a list of ``RawObservation``.
The connector's only job is *fetch -> normalize -> emit*. Correlation, scoring
and lifecycle live downstream (design doc section 4).

Connectors run in one of two modes (config.connector_mode):
  * ``fixtures`` — read a bundled JSON file; zero external calls (default).
  * ``live``     — call the real API using keys from settings.

New connectors are registered in registry.py; nothing else in the pipeline
needs to change (satisfies the "roadmap connectors drop in" requirement).
"""
from __future__ import annotations

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

FIXTURE_DIR = Path(__file__).parent / "fixtures"


@dataclass
class RawObservation:
    entity_kind: str                 # "service" | "dns_name"
    asserts_present: bool = True
    # service fields
    ip: str | None = None
    port: int | None = None
    protocol: str | None = None      # tcp|udp
    service_type: str | None = None
    tls_info: dict | None = None
    asn: str | None = None
    netblock: str | None = None
    # dns fields
    fqdn: str | None = None
    records: dict = field(default_factory=dict)
    resolves_to_ip: str | None = None
    # provenance
    observed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    raw: dict = field(default_factory=dict)


class Connector(ABC):
    name: str
    default_weight: int
    kind: str                        # push|pull_rest|pull_report|probe
    cadence: str = "on_demand"
    staleness_days: int = 14

    def __init__(self, mode: str = "fixtures", config: dict | None = None):
        self.mode = mode
        self.config = config or {}

    @abstractmethod
    def fetch(self, **kwargs) -> list[RawObservation]:
        """Return normalized observations for this cycle."""

    # --- helpers ---------------------------------------------------------- #
    def _load_fixture(self) -> list[dict]:
        path = FIXTURE_DIR / f"{self.name}.json"
        if not path.exists():
            return []
        return json.loads(path.read_text())
