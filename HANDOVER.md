# SXM — Session Handover

Companion to `easm-tool-design.md` (the authoritative spec, constraints C1–C14). That
doc says *what* to build; this one records *what exists*, *what was learned*, and *what's
left*. Read both before continuing.

Status: **v0.2 implemented + POC (no-Docker) mode.** 36 pytest tests pass.

---

## 1. Where things stand

The full platform from the design doc is built and runs two ways:

- **Docker stack** (`docker-compose.yml`): Postgres, Redis, API, Celery worker+beat,
  UI (nginx), Caddy TLS. `docker compose up -d --build`.
- **No-Docker POC**: single uvicorn process (API **and** UI) on SQLite, plus a standalone
  systemd-managed scheduler. See `deploy/POC.md`.

Core loop works end to end: ingest → correlate → confidence (T=7) → exposure/lifecycle
state machines → appear/disappear alerts → SOC UI + triage. Connectors run in **fixtures**
mode out of the box (no keys needed) and have **live** implementations ready to switch on.

### Repo layout
```
sxm/
├─ docker-compose.yml  .env.example  README.md  HANDOVER.md
├─ proxy/Caddyfile
├─ deploy/            POC.md  sxm.env.example  systemd/{sxm-api,sxm-scheduler}.service
├─ scripts/          test_api.py  check_db.py
├─ ui/index.html      (full write-enabled vanilla-JS SOC console; no build step)
└─ api/  Dockerfile  requirements.txt  conftest.py  alembic/  tests/
   └─ app/
      ├─ main.py config.py db.py models.py schemas.py security.py deps.py audit.py
      │  oidc.py seed_data.py import_csv.py run_scheduler.py
      ├─ engine/     confidence.py lifecycle.py correlation.py pipeline.py
      ├─ connectors/ base.py impl.py registry.py resolve.py fixtures/*.json
      ├─ alerting/   router.py channels.py
      ├─ tasks/      jobs.py celery_app.py
      └─ routers/    auth.py oidc.py org.py services.py dashboard.py admin.py users.py
```

### How to run / verify
- Tests: `cd api && pip install -r requirements.txt && pytest -q` → **36 pass**.
- POC: `uvicorn app.main:app --port 8000` (API+UI) and `python -m app.run_scheduler`.
- Seed inventory: `python -m app.import_csv inventory.csv` (`--dry-run` to preview).
- API smoke: `python3 scripts/test_api.py --base-url http://127.0.0.1:8000`.
- Data audit: `SXM_DATABASE_URL=… python3 scripts/check_db.py [--strict]`.

---

## 2. Things learned (read before touching code)

**Environment / dependency gotchas**
- **FastAPI/Starlette must stay pinned**: `fastapi==0.115.6`, `starlette==0.41.3`.
  Unpinned installs pull a broken combo where `include_router` silently no-ops (0 routes
  register, everything 404s). `requirements.txt` pins these; Docker is fine. In a bare
  test container, install the pins manually before running anything.
- **OIDC needs `cryptography`** (RS256/JWKS). It's in `requirements.txt`.

**Portability (Postgres ↔ SQLite)**
- JSONB is portable via `JSON().with_variant(JSONB, "postgresql")`; tests run on SQLite.
- Naive datetimes (SQLite) are coerced with `confidence.ensure_aware()` — never compare
  naive/aware directly; reuse that helper.
- SQLite under uvicorn requires `check_same_thread=False` + WAL + `busy_timeout` + FK-on.
  `db.py` applies these automatically when `SXM_DATABASE_URL` starts with `sqlite`.
  Switching DBs is **config-only** (`SXM_DATABASE_URL`), no code change — that portability
  is load-bearing, keep it.

**Architecture facts that aren't obvious**
- The API executes jobs **synchronously** (`admin.py` calls `jobs.run_full_cycle` etc.
  directly, no `.delay()`). Celery/Redis exist **only** to schedule those same functions.
  That's why the POC can drop them and use `app/run_scheduler.py` instead.
- The UI uses **relative `/api` paths**, so it must be same-origin. In Docker, nginx serves
  it; in POC, `main.py` mounts `ui/` via `StaticFiles` at `/` **after** the routers so
  `/api/*` wins.
- `/api/auth/me` returns `UserOut {id, username, enabled}` — **role is in the token
  response**, not `/me`. (This bit the test script once.)

**Domain semantics**
- Confidence score = sum of weights of the **latest per source** observation that asserts
  present **and** is fresh (within that source's `staleness_days`). T=7. Freshness is how
  disappearance works: when a scanner stops seeing a service, its weight ages out and the
  score falls below T. `compute_score` + `pipeline._evidence_for` are reused by
  `scripts/check_db.py` to detect drift between stored and recomputed values.
- **manual_import** (CSV importer): a dedicated source seeded at weight = T so a single
  import reads as `exposed`, with attribution=`owned`, lifecycle=`in_production`. Import is
  **silent** (sets exposure directly; emits no `appeared` events → no alert flood on bulk
  load). Evidence carries a **30-day grace window** (`--staleness-days`) so a stale seed
  ages out to not_observed/gone if no real scanner corroborates — it never pins a
  decommissioned service "exposed" forever.
- Alerting has **two** independent suppressors: **dedup** (per rule + service) and
  **throttle** (per rule, flap protection). Bootstrap seeds default `appeared` +
  `disappeared` rules on a console channel — tests and audits must account for those
  already existing.
- Auto-obsolete is cadence-driven (≥2 weeks below T ≈ 2 Tenable cycles); a probe asserting
  absent moves a service to `gone` immediately (`decide_exposure(probe_confirms_absent=…)`).

**Live connector shapes** (verified against current vendor docs; parsers are pure +
unit-tested, but **untested against real tenants** — no keys):
- Tenable: `X-ApiKeys` header; async **vulns export** (POST `/vulns/export` → poll
  `/status` → GET `/chunks/{id}`); services derive from findings' `port.port/protocol`.
- Shadowserver: `transform.shadowserver.org/api2/`; `apikey` in body, HMAC-SHA256 over the
  **compact** JSON in the `HMAC2` header; `reports/list` → `reports/download`.
- Shodan: `/shodan/host/search` per owned CIDR (basic tier poll).
- dnsdumpster: GET `/domain/{apex}` with `X-Api-Key`; **429 stops the cycle**.
- Each connector splits transport (`_fetch_live`) from parsing (`parse_*`) — adjust the
  parser to a tenant's real payload without touching the pipeline.

---

## 3. To do in future sessions

### Explicitly deferred by the user (top of the queue, but they said "not yet")
1. **Weekly report as a persisted week-over-week delta.** Today `/dashboard/weekly-report`
   is a live rolling-7-day count. Spec wants a scheduled job computing a real prior-week
   delta, stored as a report record, rendered from storage.
2. **Isolated async probe worker.** `nmap` currently runs **in the API process,
   synchronously** (`admin.py → jobs.run_probe`). Design wants a separate, rate-limited
   probe-worker (its own container in Docker; a queue/worker split generally). Make probe
   calls async so the request doesn't block.

### Other functional gaps vs. the design
3. **Trends chart in the UI.** Snapshots are collected and `/dashboard/trends` serves the
   series, but the UI has no visualization.
4. **dnsdumpster enumeration scheduling.** Currently one-shot, stops at 429. Needs
   day-spread budgeting for the 50/200-per-day limits across ~68 apexes.
5. **Per-protocol "gone" window.** Single global `gone_after_days`; the design flagged UDP
   needing a longer window (passive sources under-report UDP).
6. **Dashboard "by OU" distribution.** Services can be *filtered* by OU, but there's no OU
   breakdown cut on the dashboard.

### Hardening / ops (design §11, §13)
7. Scheduled **Postgres backups** (`pg_dump`) — none yet.
8. **Secrets vault** — keys currently live in `.env`.
9. **Outbound webhook signing** (HMAC on alert webhooks); **inbound Shodan webhook
   receiver** (HMAC verify + IP allowlist) — spec marked it "wired but unused"; absent.
10. **Alembic initial migration** — schema still bootstraps via `create_all`. Fine for
    fresh DBs; needed before schema evolves on a populated Postgres.

### Live validation (needs real credentials — user's side)
11. Turn on `SXM_CONNECTOR_MODE=live` and validate each connector against the real tenant;
    tweak `parse_*` to the actual payloads. Same for **OIDC** against the real IdP and
    **email/Telegram** delivery.

### POC-specific improvements
12. `run_scheduler.py` is **interval-based** (every N seconds). Celery beat used wall-clock
    crontab (e.g., "Mon 06:30"). If the POC needs specific times, add wall-clock scheduling
    (or APScheduler) to the standalone scheduler.

### Small niceties
13. `app/__init__.py` `__version__` still reads `0.1.0` (health/docs show it) though we're
    at v0.2 — bump it.
14. Open design question still unresolved: `coverage_gap` currently also flags
    candidate/off-range services. Decide whether to suppress it for non-owned services.

---

## 4. Working style notes (for the assistant)
- Javier is an experienced network/security engineer: terse, wants working code and tight
  scoping, **asks for clarification before building** when there are real forks, prefers
  Python and minimal formatting. Confirm the one or two decisions that actually change the
  implementation, state other assumptions inline, then build.
- Deliverables go out as a zip + the touched files via the file-presentation step; keep the
  README and this HANDOVER current as the cross-session source of truth.
