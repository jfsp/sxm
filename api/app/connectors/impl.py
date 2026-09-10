"""Concrete connectors with fixture and live modes.

Design: each connector separates transport (`_fetch_live`, does HTTP) from
parsing (module-level `parse_*` pure functions), so response handling is
unit-testable against sample payloads with no network. Live request/response
shapes follow each vendor's current API docs (see README for references).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import subprocess
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

import httpx

from ..config import get_settings
from .base import Connector, RawObservation
from .resolve import resolve_a

settings = get_settings()
UA = {"User-Agent": "SXM/0.2"}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _obs_from_fixture(d: dict) -> RawObservation:
    ts = d.get("observed_at")
    return RawObservation(
        entity_kind=d.get("entity_kind", "service"),
        asserts_present=d.get("asserts_present", True),
        ip=d.get("ip"), port=d.get("port"), protocol=d.get("protocol"),
        service_type=d.get("service_type"), tls_info=d.get("tls_info"),
        asn=d.get("asn"), netblock=d.get("netblock"),
        fqdn=d.get("fqdn"), records=d.get("records", {}),
        resolves_to_ip=d.get("resolves_to_ip"),
        observed_at=datetime.fromisoformat(ts) if ts else _now(),
        raw=d,
    )


# ===================== parse functions (pure) ============================== #
def parse_tenable_vulns(findings: list[dict]) -> list[RawObservation]:
    """Tenable vulns-export chunk -> one service observation per (ip,port,proto)."""
    seen: set[tuple] = set()
    out: list[RawObservation] = []
    for f in findings:
        asset = f.get("asset", {})
        port = f.get("port", {})
        ip = asset.get("ipv4") or asset.get("ipv6")
        p = port.get("port")
        if not ip or not p:
            continue
        proto = (port.get("protocol") or "tcp").lower()
        key = (ip, p, proto)
        if key in seen:
            continue
        seen.add(key)
        out.append(RawObservation(
            entity_kind="service", ip=ip, port=int(p), protocol=proto,
            service_type=port.get("service"), asn=asset.get("network_id"),
            asserts_present=True, raw=f,
        ))
    return out


def parse_shadowserver_rows(rows: list[dict]) -> list[RawObservation]:
    out = []
    for r in rows:
        ip = r.get("ip")
        p = r.get("port")
        if not ip or not p:
            continue
        out.append(RawObservation(
            entity_kind="service", ip=ip, port=int(p),
            protocol=(r.get("protocol") or "tcp").lower(),
            service_type=r.get("service") or r.get("type"),
            asn=str(r.get("asn")) if r.get("asn") else None,
            asserts_present=True, raw=r,
        ))
    return out


def parse_shodan_search(data: dict) -> list[RawObservation]:
    out = []
    for m in data.get("matches", []):
        ip = m.get("ip_str")
        p = m.get("port")
        if not ip or not p:
            continue
        asn = m.get("asn")
        out.append(RawObservation(
            entity_kind="service", ip=ip, port=int(p),
            protocol=(m.get("transport") or "tcp").lower(),
            service_type=m.get("product") or m.get("_shodan", {}).get("module"),
            asn=str(asn) if asn else None,
            tls_info=({"cert": m["ssl"].get("cert", {})} if m.get("ssl") else None),
            asserts_present=True, raw=m,
        ))
    return out


def parse_dnsdumpster(data: dict, resolve_missing: bool = False) -> list[RawObservation]:
    """Official dnsdumpster response -> dns_name observations (+ resolved host hints)."""
    out = []
    for rec in data.get("a", []):
        host = rec.get("host")
        if not host:
            continue
        ips = rec.get("ips", [])
        first = ips[0] if ips else {}
        ip = first.get("ip")
        if not ip and resolve_missing:
            resolved = resolve_a(host)
            ip = resolved[0] if resolved else None
        out.append(RawObservation(
            entity_kind="dns_name", fqdn=host,
            records={"A": [i.get("ip") for i in ips] or ([ip] if ip else [])},
            resolves_to_ip=ip,
            asn=str(first.get("asn")) if first.get("asn") else None,
            netblock=first.get("range") or first.get("netblock"),
            asserts_present=True, raw=rec,
        ))
    return out


def parse_generic_services(rows: list[dict]) -> list[RawObservation]:
    """Shared parser for feeds returning [{ip,port,protocol,service,asn}] (ELSA/SOCRadar)."""
    out = []
    for r in rows:
        ip = r.get("ip") or r.get("ip_address")
        p = r.get("port")
        if not ip or not p:
            continue
        out.append(RawObservation(
            entity_kind="service", ip=ip, port=int(p),
            protocol=(r.get("protocol") or "tcp").lower(),
            service_type=r.get("service") or r.get("service_type"),
            asn=str(r.get("asn")) if r.get("asn") else None,
            asserts_present=bool(r.get("present", True)), raw=r,
        ))
    return out


def parse_nmap_xml(xml_text: str) -> bool:
    """Return True if any scanned port is 'open'."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return False
    for state in root.iter("state"):
        if state.get("state") == "open":
            return True
    return False


# ===================== connectors ========================================= #
class TenableConnector(Connector):
    name = "tenable"; default_weight = 5; kind = "pull_rest"; cadence = "weekly"; staleness_days = 14

    def fetch(self, **kwargs) -> list[RawObservation]:
        if self.mode == "fixtures":
            return [_obs_from_fixture(d) for d in self._load_fixture()]
        return self._fetch_live(**kwargs)

    def _headers(self):
        return {**UA, "X-ApiKeys":
                f"accessKey={settings.tenable_access_key};secretKey={settings.tenable_secret_key}",
                "Content-Type": "application/json", "Accept": "application/json"}

    def _fetch_live(self, *, poll_interval: float = 5.0, max_polls: int = 120, **_) -> list[RawObservation]:
        base = settings.tenable_url
        with httpx.Client(timeout=60, headers=self._headers()) as c:
            r = c.post(f"{base}/vulns/export",
                       json={"num_assets": 5000, "filters": {"state": ["OPEN", "REOPENED"]}})
            r.raise_for_status()
            uuid = r.json()["export_uuid"]
            done = set()
            out: list[RawObservation] = []
            for _i in range(max_polls):
                st = c.get(f"{base}/vulns/export/{uuid}/status").json()
                for chunk in st.get("chunks_available", []):
                    if chunk in done:
                        continue
                    data = c.get(f"{base}/vulns/export/{uuid}/chunks/{chunk}").json()
                    out.extend(parse_tenable_vulns(data))
                    done.add(chunk)
                if st.get("status") in ("FINISHED", "ERROR") and \
                        len(done) >= len(st.get("chunks_available", [])):
                    break
                time.sleep(poll_interval)
            return out


class ShadowserverConnector(Connector):
    name = "shadowserver"; default_weight = 3; kind = "pull_report"; cadence = "daily"; staleness_days = 3

    def fetch(self, **kwargs) -> list[RawObservation]:
        if self.mode == "fixtures":
            return [_obs_from_fixture(d) for d in self._load_fixture()]
        return self._fetch_live(**kwargs)

    def _call(self, client: httpx.Client, method: str, request: dict):
        request = {**request, "apikey": settings.shadowserver_api_key}
        body = json.dumps(request, separators=(",", ":"))
        sig = hmac.new(settings.shadowserver_secret.encode(), body.encode(),
                       hashlib.sha256).hexdigest()
        resp = client.post(settings.shadowserver_url + method, content=body,
                           headers={**UA, "HMAC2": sig, "Content-Type": "application/json"})
        resp.raise_for_status()
        return resp.json()

    def _fetch_live(self, *, date: str | None = None, **_) -> list[RawObservation]:
        date = date or _now().strftime("%Y-%m-%d")
        types = [t.strip() for t in settings.shadowserver_report_types.split(",") if t.strip()]
        out: list[RawObservation] = []
        with httpx.Client(timeout=60) as c:
            reports = self._call(c, "reports/list", {"date": date})
            for rep in reports:
                if types and rep.get("type") not in types:
                    continue
                rows = self._call(c, "reports/download", {"id": rep.get("id")})
                out.extend(parse_shadowserver_rows(rows))
        return out


class ShodanConnector(Connector):
    name = "shodan"; default_weight = 2; kind = "pull_rest"; cadence = "poll"; staleness_days = 10

    def fetch(self, **kwargs) -> list[RawObservation]:
        if self.mode == "fixtures":
            return [_obs_from_fixture(d) for d in self._load_fixture()]
        return self._fetch_live(**kwargs)

    def _fetch_live(self, *, targets: list[str] | None = None, **_) -> list[RawObservation]:
        # targets = owned CIDRs; basic tier poll of /shodan/host/search
        out: list[RawObservation] = []
        queries = [f"net:{cidr}" for cidr in (targets or [])]
        with httpx.Client(timeout=60, headers=UA) as c:
            for q in queries:
                r = c.get("https://api.shodan.io/shodan/host/search",
                          params={"key": settings.shodan_api_key, "query": q})
                r.raise_for_status()
                out.extend(parse_shodan_search(r.json()))
        return out


class DnsdumpsterConnector(Connector):
    name = "dnsdumpster"; default_weight = 1; kind = "pull_rest"; cadence = "enum"; staleness_days = 30

    def fetch(self, **kwargs) -> list[RawObservation]:
        if self.mode == "fixtures":
            return [_obs_from_fixture(d) for d in self._load_fixture()]
        return self._fetch_live(**kwargs)

    def _fetch_live(self, *, targets: list[str] | None = None, **_) -> list[RawObservation]:
        out: list[RawObservation] = []
        with httpx.Client(timeout=60, headers={**UA, "X-Api-Key": settings.dnsdumpster_api_key}) as c:
            for apex in (targets or []):
                r = c.get(f"{settings.dnsdumpster_url}/domain/{apex}")
                if r.status_code == 429:
                    break  # rate limited; stop this cycle
                r.raise_for_status()
                out.extend(parse_dnsdumpster(r.json(), resolve_missing=settings.resolve_enumerated))
        return out


class ElsaConnector(Connector):
    name = "elsa"; default_weight = 3; kind = "pull_rest"; cadence = "periodic"; staleness_days = 14

    def fetch(self, **kwargs) -> list[RawObservation]:
        if self.mode == "fixtures":
            return [_obs_from_fixture(d) for d in self._load_fixture()]
        return self._fetch_live(**kwargs)

    def _fetch_live(self, **_) -> list[RawObservation]:
        # ELSA (CCN-CERT DELTA90) national ASM feed; scans from source port 42104.
        # Endpoint/schema are org-specific; expects JSON list of service rows.
        if not settings.elsa_url:
            raise NotImplementedError("SXM_ELSA_URL not configured")
        with httpx.Client(timeout=60, headers={**UA, "Authorization": f"Bearer {settings.elsa_api_key}"}) as c:
            r = c.get(settings.elsa_url)
            r.raise_for_status()
            data = r.json()
        return parse_generic_services(data if isinstance(data, list) else data.get("results", []))


class SocradarConnector(Connector):
    name = "socradar"; default_weight = 2; kind = "pull_rest"; cadence = "periodic"; staleness_days = 14

    def fetch(self, **kwargs) -> list[RawObservation]:
        if self.mode == "fixtures":
            return [_obs_from_fixture(d) for d in self._load_fixture()]
        return self._fetch_live(**kwargs)

    def _fetch_live(self, **_) -> list[RawObservation]:
        # SOCRadar EASM REST API; endpoint/schema org-specific.
        with httpx.Client(timeout=60, headers={**UA, "API-KEY": settings.socradar_api_key}) as c:
            r = c.get(f"{settings.socradar_url}/company/attack-surface")
            r.raise_for_status()
            data = r.json()
        return parse_generic_services(data if isinstance(data, list) else data.get("results", []))


class NmapProbeConnector(Connector):
    name = "nmap_probe"; default_weight = 4; kind = "probe"; cadence = "on_demand"; staleness_days = 3

    def fetch(self, *, ip: str, port: int, protocol: str = "tcp", **kwargs) -> list[RawObservation]:
        if self.mode == "fixtures":
            present = (port % 2) == 0
            return [RawObservation(entity_kind="service", asserts_present=present,
                                   ip=ip, port=port, protocol=protocol, service_type="probed",
                                   raw={"stub": True, "present": present})]
        return self._fetch_live(ip=ip, port=port, protocol=protocol, **kwargs)

    def _fetch_live(self, *, ip: str, port: int, protocol: str = "tcp", **_) -> list[RawObservation]:
        scan = "-sU" if protocol == "udp" else "-sT"
        try:
            proc = subprocess.run(
                ["nmap", "-Pn", "-p", str(port), scan, ip, "-oX", "-"],
                capture_output=True, text=True, timeout=120,
            )
            present = parse_nmap_xml(proc.stdout)
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            return [RawObservation(entity_kind="service", asserts_present=False, ip=ip,
                                   port=port, protocol=protocol, raw={"error": str(exc)})]
        return [RawObservation(entity_kind="service", asserts_present=present, ip=ip,
                               port=port, protocol=protocol, service_type="probed",
                               raw={"nmap": True, "present": present})]
