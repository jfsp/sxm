#!/usr/bin/env python3
"""End-to-end API smoke test for a running SXM instance.

Zero third-party deps (stdlib urllib) so it runs from anywhere. Exercises auth, the
ingest cycle, service/dashboard reads, RBAC enforcement, and admin writes, printing a
PASS/FAIL line per check and exiting non-zero if anything fails.

    python3 scripts/test_api.py --base-url http://127.0.0.1:8000 --user admin --password ...

Defaults come from env: SXM_BASE_URL, SXM_ADMIN_USERNAME, SXM_ADMIN_PASSWORD.
Non-destructive: it only creates one throwaway analyst account (left disabled).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

PASS, FAIL = 0, 0
FAILURES: list[str] = []


def _req(method: str, url: str, *, token=None, data=None, form=None, timeout=30):
    headers = {}
    body = None
    if token:
        headers["Authorization"] = "Bearer " + token
    if form is not None:
        body = urllib.parse.urlencode(form).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    elif data is not None:
        body = json.dumps(data).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            return resp.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            payload = json.loads(raw)
        except Exception:
            payload = raw.decode(errors="replace")
        return e.code, payload


def check(name: str, cond: bool, detail: str = ""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  PASS  {name}")
    else:
        FAIL += 1
        FAILURES.append(name)
        print(f"  FAIL  {name}  {detail}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", default=os.getenv("SXM_BASE_URL", "http://127.0.0.1:8000"))
    ap.add_argument("--user", default=os.getenv("SXM_ADMIN_USERNAME", "admin"))
    ap.add_argument("--password", default=os.getenv("SXM_ADMIN_PASSWORD", "admin"))
    args = ap.parse_args()
    base = args.base_url.rstrip("/")
    api = base + "/api"
    print(f"Testing {base}")

    # health
    st, body = _req("GET", api + "/health")
    check("health 200", st == 200 and (body or {}).get("status") == "ok", f"status={st}")

    # auth
    st, body = _req("POST", api + "/auth/token", form={"username": args.user, "password": args.password})
    token = (body or {}).get("access_token") if st == 200 else None
    check("admin login", token is not None, f"status={st} body={body}")
    if not token:
        _summary()
        return 1

    st, body = _req("GET", api + "/auth/me", token=token)
    check("me returns current user", st == 200 and (body or {}).get("username") == args.user,
          f"status={st} body={body}")

    # wrong password rejected
    st, _ = _req("POST", api + "/auth/token", form={"username": args.user, "password": "definitely-wrong"})
    check("bad password 401", st == 401, f"status={st}")

    # run a cycle
    st, body = _req("POST", api + "/admin/run-cycle", token=token, data={})
    check("run-cycle 200", st == 200, f"status={st} body={body}")

    # services
    st, services = _req("GET", api + "/services", token=token)
    check("list services 200", st == 200 and isinstance(services, list), f"status={st}")
    services = services if isinstance(services, list) else []
    if services:
        sid = services[0]["id"]
        st, detail = _req("GET", f"{api}/services/{sid}", token=token)
        check("service detail", st == 200 and "present_sources" in (detail or {}), f"status={st}")

    # dashboards
    for ep in ("summary", "events", "dns-dangling", "weekly-report", "trends"):
        st, _ = _req("GET", f"{api}/dashboard/{ep}", token=token)
        check(f"dashboard/{ep} 200", st == 200, f"status={st}")

    # sources present
    st, sources = _req("GET", api + "/admin/sources", token=token)
    names = {s["name"] for s in sources} if isinstance(sources, list) else set()
    check("core sources registered",
          {"tenable", "shadowserver", "shodan", "dnsdumpster", "nmap_probe"} <= names,
          f"got={sorted(names)}")

    # RBAC: create a throwaway analyst and verify restrictions
    uname = f"apitest_{int(time.time())}"
    st, _ = _req("POST", api + "/admin/users", token=token,
                 data={"username": uname, "password": "pw-poc-123", "role": "analyst"})
    check("create analyst user", st == 200, f"status={st}")
    st, body = _req("POST", api + "/auth/token", form={"username": uname, "password": "pw-poc-123"})
    atoken = (body or {}).get("access_token")
    check("analyst login", atoken is not None, f"status={st}")
    if atoken:
        st, _ = _req("GET", api + "/admin/users", token=atoken)
        check("analyst blocked from /admin/users (403)", st == 403, f"status={st}")
        st, _ = _req("GET", api + "/services", token=atoken)
        check("analyst can read services (200)", st == 200, f"status={st}")
    # leave the throwaway account disabled
    st, alist = _req("GET", api + "/admin/users", token=token)
    if isinstance(alist, list):
        uid = next((u["id"] for u in alist if u["username"] == uname), None)
        if uid:
            _req("PATCH", f"{api}/admin/users/{uid}", token=token, data={"enabled": False})

    # admin alert config write
    st, ch = _req("POST", api + "/admin/alert-channels", token=token,
                  data={"kind": "console", "config": {}, "enabled": True})
    check("create alert channel", st == 200, f"status={st}")
    if st == 200:
        st, _ = _req("POST", api + "/admin/alert-rules", token=token,
                     data={"event_type": "appeared", "channel_id": ch["id"],
                           "dedup_window_seconds": 3600, "throttle_seconds": 0})
        check("create alert rule", st == 200, f"status={st}")

    return _summary()


def _summary() -> int:
    print(f"\n{PASS} passed, {FAIL} failed")
    if FAILURES:
        print("failed: " + ", ".join(FAILURES))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
