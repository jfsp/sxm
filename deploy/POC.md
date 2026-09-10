# SXM — no-Docker POC deployment

Single-host bare-metal setup: one uvicorn process (API + UI) on **SQLite**, plus a
**standalone scheduler** as a systemd service. No Postgres, Redis, Celery, nginx, Caddy,
or Docker.

## 1. Install

```bash
sudo useradd --system --home /opt/sxm --shell /usr/sbin/nologin sxm
sudo mkdir -p /opt/sxm/data
# copy the repo so that the app lives at /opt/sxm/api/app
sudo cp -r sxm/api /opt/sxm/api
sudo cp -r sxm/ui  /opt/sxm/ui          # UI served by the API (../ui relative to app)

cd /opt/sxm/api
sudo python3 -m venv .venv
sudo .venv/bin/pip install -r requirements.txt
sudo chown -R sxm:sxm /opt/sxm
```

Python 3.11+ required (3.12 recommended). `nmap` only needed for live probing
(`sudo apt install nmap`); fixtures mode needs nothing extra.

## 2. Configure

```bash
sudo cp sxm/deploy/sxm.env.example /opt/sxm/sxm.env
sudo -e /opt/sxm/sxm.env      # set SXM_SECRET_KEY (openssl rand -hex 32) + SXM_ADMIN_PASSWORD
sudo chown sxm:sxm /opt/sxm/sxm.env && sudo chmod 600 /opt/sxm/sxm.env
```

## 3. Install services

```bash
sudo cp sxm/deploy/systemd/sxm-api.service       /etc/systemd/system/
sudo cp sxm/deploy/systemd/sxm-scheduler.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now sxm-api sxm-scheduler
sudo systemctl status sxm-api sxm-scheduler
journalctl -u sxm-scheduler -f          # watch cycles run
```

The API initializes the DB (schema + seed) on first boot; the scheduler waits 5s
(`ExecStartPre`) so it doesn't race that. `run-on-start` runs one full cycle immediately
so you have data right away.

## 4. Seed real inventory (optional)

```bash
sudo -u sxm SXM_DATABASE_URL="sqlite+pysqlite:////opt/sxm/data/sxm.db" \
  /opt/sxm/api/.venv/bin/python -m app.import_csv /path/to/inventory.csv
```

## 5. Verify

```bash
cd sxm
python3 scripts/test_api.py  --base-url http://127.0.0.1:8000   # API smoke
SXM_DATABASE_URL="sqlite+pysqlite:////opt/sxm/data/sxm.db" \
  python3 scripts/check_db.py                                    # data-consistency audit
```

Open `http://127.0.0.1:8000/` for the SOC console (log in as admin).

## Notes / trade-offs

* **SQLite concurrency**: the engine enables WAL + a 30s busy timeout and foreign-key
  enforcement, so the API and scheduler can share the file. Fine at POC scale; move to
  Postgres for production by changing only `SXM_DATABASE_URL`.
* **No TLS**: bind to `127.0.0.1` and put it behind an SSH tunnel or a reverse proxy if
  you need remote access. The Docker stack (Caddy) is the TLS path for production.
* **Scheduling**: intervals are seconds via `SXM_SCHEDULER_*`. The scheduler is
  independent of the API; restart either without affecting the other.
