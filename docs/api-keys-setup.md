# Enabling connector APIs

How to obtain and configure credentials for each source in `api/app/connectors/impl.py`
so `SXM_CONNECTOR_MODE=live` works. Fixtures mode needs none of this. Every key below
goes in `.env` (see `.env.example`); restart (`docker compose up -d --build` or the
uvicorn/scheduler processes in POC mode) to pick up changes.

Scopes noted here separate service-only read access from full seat access:
grant the narrowest scope the portal offers — SXM only reads exposure data, so
avoid vendor account roles/API scopes that also permit config or user changes.

---

## Tenable (Tenable.io / Tenable Vulnerability Management)

Required for `TenableConnector` (`vulns/export`).

1. Log in to your Tenable.io/Tenable.sc console with an account that has
   **Administrator** or **Scan Manager** role (API key generation requires this).
2. Go to **Settings → My Account → API Keys**.
3. Click **Generate**. Copy the **Access Key** and **Secret Key** immediately —
   the secret is shown once.
4. Confirm the account/license covers `/vulns/export` (standard on VM licenses) and
   that the scan already covers your owned IP ranges (SXM only reads findings, it
   doesn't trigger scans).

```
SXM_TENABLE_URL=https://cloud.tenable.com     # or your self-hosted Tenable.sc URL
SXM_TENABLE_ACCESS_KEY=...
SXM_TENABLE_SECRET_KEY=...
```

Regenerating a key immediately revokes the old one — rotate during a maintenance
window, not mid-cycle.

## Shadowserver (Alliance / free reporting program)

Required for `ShadowserverConnector` (`reports/list`, `reports/download`, HMAC-signed).

1. Request access at https://www.shadowserver.org/what-we-do/network-reporting/get-reports/
   (org must be a recognized network owner/CERT/ISP; approval is manual, expect a few
   days).
2. Once approved, the portal issues an **API key** and **API secret** — these are a
   distinct HMAC keypair, not your report-portal login.
3. Verify your ASN/CIDR ranges are the ones enrolled for reporting — Shadowserver only
   returns rows for enrolled netblocks, whatever `SXM_SHADOWSERVER_REPORT_TYPES` requests.

```
SXM_SHADOWSERVER_URL=https://transform.shadowserver.org/api2/
SXM_SHADOWSERVER_API_KEY=...
SXM_SHADOWSERVER_SECRET=...
SXM_SHADOWSERVER_REPORT_TYPES=scan_http,scan_https,scan_ssh,populate
```

Report type names must match what Shadowserver enrolled you for; mismatches silently
return nothing (connector just sees an empty `reports/list`), not an error.

## Shodan

Required for `ShodanConnector` (`/shodan/host/search`, polled per owned CIDR).

1. Create an account at https://account.shodan.io/register.
2. A **Basic** (or higher) paid membership is required for API search access — the
   free tier's API key exists but `host/search` needs a paid plan (design doc C5 notes
   Shodan basic can't cover the full ~3,100-IP estate; it's supplementary, not a primary
   monitor).
3. Copy the key from https://account.shodan.io/ (front page, "API Key" box).

```
SXM_SHODAN_API_KEY=...
```

Search credits are metered per plan; `net:<cidr>` queries run once per seeded CIDR
each poll cycle — size the plan to the CIDR count in your seed data, not just IP count.

If you ever wire up the inbound Shodan on-demand-scan webhook (mentioned as a roadmap
item in `HANDOVER.md`), verify the `SHODAN-SIGNATURE-SHA1` HMAC and allowlist Shodan's
source IPs at the ingress — that's a separate, optional feature from the search API key
above.

## DNSdumpster (official API, not the free web UI)

Required for `DnsdumpsterConnector` (`GET /domain/{apex}`).

1. Sign up for the paid API at https://dnsdumpster.com/ → **API** (this is a distinct
   product from the free browser-based lookup tool; the free tier has no API key).
2. Pick a plan based on request volume: the connector calls once per owned apex domain
   per enumeration cycle (68 apexes in the reference deployment) — check the plan's
   daily quota (commonly 50–200/day) against your apex count, since the connector stops
   the whole cycle on the first `HTTP 429` it hits (see `HANDOVER.md` §3.4 — day-spread
   budgeting across apexes is a known gap).
3. Copy the API key from the dashboard.

```
SXM_DNSDUMPSTER_URL=https://api.dnsdumpster.com
SXM_DNSDUMPSTER_API_KEY=...
```

## ELSA (CCN-CERT DELTA90 national ASM feed) — roadmap, org-specific

Required for `ElsaConnector`. Endpoint and payload schema are issued per-organization
by CCN-CERT (Spanish national CERT); there is no self-service signup. Request onboarding
through your organization's CCN-CERT liaison/DELTA90 contact, who will provide the feed
URL and a bearer token.

```
SXM_ELSA_URL=...          # provided by CCN-CERT for your org
SXM_ELSA_API_KEY=...      # bearer token
```

The connector raises `NotImplementedError` until `SXM_ELSA_URL` is set, and ships
**disabled** in the scheduler — enable it under **Sources** in the UI once configured
(`parse_generic_services` may need adjusting to your tenant's exact field names, per
`HANDOVER.md`).

## SOCRadar — roadmap, org-specific

Required for `SocradarConnector` (`GET {base}/company/attack-surface`).

1. Requires a SOCRadar EASM module subscription — contact SOCRadar sales/your account
   team; there's no self-service API key page for this endpoint.
2. Your account team provisions an **API-KEY** scoped to the EASM/attack-surface module.

```
SXM_SOCRADAR_URL=https://platform.socradar.com/api
SXM_SOCRADAR_API_KEY=...
```

Ships **disabled** like ELSA — enable under **Sources** in the UI once configured, and
verify the response shape against `parse_generic_services` (org-specific).

## nmap probe — no API key

`NmapProbeConnector` runs `nmap` as a local subprocess (admin-triggered, or automatic
under `SXM_AUTO_PROBE_ON_DOUBT`). No account or key — just `nmap` installed on the host
running the API/scheduler (`apt install nmap` — see `deploy/POC.md`). Nothing to
configure beyond making sure the process has permission to raise raw sockets for SYN
scans if you change the scan flags in `impl.py` (the default `-sT`/`-sU` don't need it).

---

## Checklist to go live

1. Fill in the keys above in `.env` for the sources you actually subscribe to.
2. Set `SXM_CONNECTOR_MODE=live`.
3. Leave `elsa`/`socradar` disabled in **Sources** (admin UI) until their org-specific
   endpoints are confirmed — they ship disabled by default for exactly this reason.
4. Rebuild/restart (`docker compose up -d --build`, or restart the POC uvicorn +
   `run_scheduler` processes).
5. Trigger one manual cycle (**run cycle** in the UI, or
   `POST /api/admin/run-cycle`) and check `scripts/check_db.py` / the SOC console for
   observations landing from each newly-enabled source before relying on the schedule.
6. Store the keys in a proper secrets store for production — `.env` is fine for a POC,
   but `HANDOVER.md` §3 flags a secrets vault as still outstanding.
