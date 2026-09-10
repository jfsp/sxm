# Surface Exposure Management (SXM) — v0.2

Full implementation of the EASM platform from `easm-tool-design.md`. v0.2 completes
the parts deferred in v0.1: **live connectors** for every source, **ELSA + SOCRadar**
roadmap feeds, **email + Telegram** alerting, **OIDC SSO**, **user management**,
**retention**, **auto-probe-on-doubt**, discovery DNS resolution, and a **full
write-enabled SOC console**.

Tested: **30 pytest tests** (confidence, state machines, connector parsers, OIDC role
mapping, throttle, retention, auto-probe, e2e pipeline) + HTTP smoke incl. RBAC.

---

## Status vs. design doc

| Area | Status |
|---|---|
| Data model, RBAC (admin/analyst/manager), audit log, local JWT | ✅ |
| Ownership seeds + attribution; manual OU assignment | ✅ |
| Connectors — Tenable, Shadowserver, Shodan, dnsdumpster, nmap: **fixtures + live** | ✅ |
| Roadmap connectors — **ELSA, SOCRadar** (registered, seeded disabled) | ✅ |
| Weighted confidence (T=7), doubt band, coverage-gap | ✅ |
| Exposure + lifecycle state machines, auto-obsolete (≥2 wk) | ✅ |
| Appear/disappear alerts → **console, webhook, email, Telegram** + dedup **+ throttle** | ✅ |
| Discovery expansion — DNS enum → resolve → off-range host/candidate | ✅ |
| Probe — admin-triggered **+ auto-probe-on-doubt toggle** (real nmap in live mode) | ✅ |
| Retention purge of raw observations | ✅ |
| **OIDC SSO** (provider-agnostic) + **user management** | ✅ |
| Dashboards, weekly report, trends/snapshots, **write-enabled UI** | ✅ |
| docker-compose single VM, Caddy TLS ingress | ✅ |

Alembic remains the path for schema changes (v1 bootstraps via `create_all`).

---

## Quick start (fixtures mode — no subscriptions needed)

```bash
cp .env.example .env
# EDIT: SXM_SECRET_KEY (openssl rand -hex 32), SXM_ADMIN_PASSWORD, POSTGRES_PASSWORD
docker compose up -d --build
docker compose logs -f api          # wait for "Bootstrap complete."
```

Open `https://localhost/` (internal CA — accept warning), log in as admin. Click
**run cycle** in the header, or:

```bash
TOKEN=$(curl -sk https://localhost/api/auth/token -d "username=admin&password=YOUR_PW" | jq -r .access_token)
curl -sk -X POST https://localhost/api/admin/run-cycle -H "Authorization: Bearer $TOKEN" | jq
```

API docs at `https://localhost/docs`.

### No-Docker POC (single process + SQLite)

For a low-overhead POC you can skip Docker/Postgres/Redis/Celery entirely: run the API
(which also serves the UI) on SQLite, with a standalone systemd-managed scheduler in
place of Celery beat. See **`deploy/POC.md`**; unit files are in `deploy/systemd/` and a
sample env in `deploy/sxm.env.example`.

```bash
cd api && python -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt
export SXM_DATABASE_URL="sqlite+pysqlite:///./sxm.db" SXM_SECRET_KEY="$(openssl rand -hex 32)" SXM_ADMIN_PASSWORD=pw
uvicorn app.main:app --port 8000            # API + UI at http://127.0.0.1:8000
python -m app.run_scheduler                 # separate process: periodic cycle/snapshot/purge
```

### Operational scripts

- `scripts/test_api.py` — stdlib-only end-to-end API smoke (auth, cycle, RBAC, dashboards,
  admin writes). `python3 scripts/test_api.py --base-url http://127.0.0.1:8000`.
- `scripts/check_db.py` — data-consistency auditor: referential integrity, service
  provenance, exposure/lifecycle coherence, score/exposure drift vs the engine,
  attribution vs seeds, and scheduling/alerting readiness.
  `SXM_DATABASE_URL=… python3 scripts/check_db.py [--strict]`.

---

## Seeding from a CSV inventory

Bulk-load a known inventory as the starting point:

```bash
docker compose exec api python -m app.import_csv /path/to/inventory.csv
docker compose exec api python -m app.import_csv /path/to/inventory.csv --dry-run
```

CSV columns (header-matched case-insensitively; positional fallback in this order):

```
IP, DNS name, Port number, Port type (TCP/UDP), Organisational unit responsible, Notes
```

Per row, any subset works: `IP+port` → host+service; `IP+DNS` → name resolving to the
host; `DNS only` → a name with nothing behind it; `Notes` → an annotation on the service.
OUs are auto-created by name.

Imported services are treated as authoritative: `attribution=owned`,
`lifecycle=in_production`, and seeded via a `manual_import` source at weight = T so they
read as **exposed** immediately — without emitting appeared events (no alert flood). That
evidence carries a **grace window** (`--staleness-days`, default 30): real scanners are
expected to corroborate within it; if none do, the service ages out to
not_observed/gone on its own. The import is **idempotent** — re-running refreshes the
grace window and never duplicates rows, names, OUs, or identical notes.

---


Set `SXM_CONNECTOR_MODE=live` and the relevant keys in `.env`, then
`docker compose up -d --build`. Connectors are implemented to current vendor APIs:

- **Tenable** — `X-ApiKeys` header; async **vulns export** (`POST /vulns/export` →
  poll `/status` → download `/chunks/{id}`); services derived from findings that
  carry `port.port`/`port.protocol`.
- **Shadowserver** — `transform.shadowserver.org/api2/`; `apikey` in body, **HMAC-SHA256**
  over the compact JSON sent in the `HMAC2` header; `reports/list` → `reports/download`.
  Report types via `SXM_SHADOWSERVER_REPORT_TYPES`.
- **Shodan** — basic-tier `/shodan/host/search` polled per owned CIDR seed.
- **dnsdumpster** — `GET /domain/{apex}` with `X-Api-Key` per owned Domain seed;
  429 stops the cycle (rate limits). Enumerated names are resolved
  (`SXM_RESOLVE_ENUMERATED`) so off-range IPs surface as hosts/candidates.
- **nmap probe** — `nmap -Pn -p<port> -sT/-sU <ip> -oX -`, parsed for `open`.
- **ELSA / SOCRadar** — generic pull parsers (`[{ip,port,protocol,service,asn}]`);
  endpoints are org-specific, set `SXM_ELSA_URL` / `SXM_SOCRADAR_*` and enable in the UI.

Each connector separates transport (`_fetch_live`) from parsing (`parse_*`), and the
parsers are unit-tested against sample payloads — adjust parsing to your tenant's exact
schema in `api/app/connectors/impl.py` without touching the pipeline.

---

## Alerting channels

Configure under **alerts** (admin). Channel `config` JSON:

- webhook: `{"url":"https://…"}`
- email: `{"to":["soc@x"],"from":"…","host":"…","port":587,"user":"…","password":"…"}`
  (falls back to `SXM_SMTP_*`)
- telegram: `{"bot_token":"…","chat_id":"…"}`

Rules map event type (+ optional OU scope) → channel, with **dedup** (per service) and
**throttle** (per rule, flap protection). `appeared` fires only on first confirmed
sighting (score ≥ T).

---

## SSO (OIDC)

Set `SXM_OIDC_ENABLED=true` + issuer/client/redirect and a `SXM_OIDC_ROLE_MAP`
(claim value → role). Works with any OIDC IdP (Keycloak, Azure AD, Okta, Google) via
discovery + Authorization Code flow; the ID token is validated (RS256/JWKS), the user is
provisioned, and the IdP is source-of-truth for role each login. Local accounts still
work — the login page offers both. SAML is not implemented (OIDC seam covers the common
IdPs); it can be added behind the same `oidc.py` seam.

## Users

Admin **users** tab (or API `/api/admin/users`): create local users, set role,
enable/disable, reset password. OIDC users are auto-provisioned on first SSO login.

## Toggles & retention

- `SXM_AUTO_PROBE_ON_DOUBT` (default off, C9): after each cycle, owned services in the
  doubt band get an nmap probe (capped by `SXM_AUTO_PROBE_MAX_PER_CYCLE`; candidates
  excluded per §13).
- `SXM_DAILY_SNAPSHOTS` (default off, C12).
- `SXM_OBSERVATION_RETENTION_DAYS` (default 90): weekly beat purges aged raw observation
  payloads; derived state is kept.

## Scheduled jobs (Celery beat, UTC)

Daily 06:00 pull+reconcile(+auto-probe) · weekly Mon 06:30 snapshot (+ daily if enabled)
· weekly Sun 03:00 retention purge.

---

## RBAC

| | admin | analyst | manager |
|---|---|---|---|
| Dashboards / reports | ✓ | ✓ | ✓ |
| Lifecycle, OU assign, annotations | ✓ | ✓ | — |
| Trigger probe | ✓ | — | — |
| Sources, seeds, OUs, alerts, users, run-cycle | ✓ | — | — |

Every mutation writes `audit_log`.

## Tests

```bash
cd api && pip install -r requirements.txt && pytest -q      # 30 tests
```

## Security hardening

Change admin password + `SXM_SECRET_KEY` before exposure; api/ui publish no host ports
(Caddy is sole ingress); keep source keys in a vault for production; nmap worker is
rate-limited + audited; schedule `pg_dump` backups; if a Shodan webhook is ever enabled,
verify `SHODAN-SIGNATURE-SHA1` HMAC and IP-allowlist Shodan at the proxy.

## Layout

```
sxm/
├─ docker-compose.yml  .env.example  proxy/Caddyfile  ui/index.html
└─ api/  Dockerfile  requirements.txt  alembic/  tests/
   └─ app/
      ├─ main.py config.py db.py models.py schemas.py security.py deps.py audit.py oidc.py seed_data.py
      ├─ engine/     confidence.py lifecycle.py correlation.py pipeline.py
      ├─ connectors/ base.py impl.py registry.py resolve.py fixtures/*.json
      ├─ alerting/   router.py channels.py
      ├─ tasks/      jobs.py celery_app.py
      └─ routers/    auth.py oidc.py org.py services.py dashboard.py admin.py users.py
```
