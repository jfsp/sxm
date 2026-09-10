from __future__ import annotations

import logging
import time
from contextlib import asynccontextmanager

from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text

from . import __version__
from .config import get_settings
from .db import engine
from .seed_data import bootstrap
from .routers import auth, org, services, dashboard, admin, users, oidc

settings = get_settings()

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("sxm")


def _wait_for_db(retries: int = 30, delay: float = 1.0) -> None:
    for i in range(retries):
        try:
            with engine.connect() as c:
                c.execute(text("SELECT 1"))
            return
        except Exception as exc:  # noqa: BLE001
            log.info("waiting for db (%s/%s): %s", i + 1, retries, exc)
            time.sleep(delay)
    raise RuntimeError("database not reachable")


@asynccontextmanager
async def lifespan(app: FastAPI):
    _wait_for_db()
    bootstrap()
    yield


app = FastAPI(title="Surface Exposure Management", version=__version__, lifespan=lifespan)

app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)

for r in (auth.router, oidc.router, org.router, services.router,
          dashboard.router, admin.router, users.router):
    app.include_router(r)


@app.get("/api/health")
def health():
    return {"status": "ok", "version": __version__}


# POC no-Docker: serve the SPA from the same origin so its relative /api calls work
# (nginx does this in the Docker stack). Mounted last so /api/* routes win.
if settings.serve_ui:
    _ui = Path(__file__).resolve().parents[2] / "ui"
    if _ui.is_dir():
        app.mount("/", StaticFiles(directory=str(_ui), html=True), name="ui")
        log.info("serving UI from %s", _ui)
