from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SXM_", env_file=".env", extra="ignore")

    # --- Core ---
    database_url: str = "postgresql+psycopg2://sxm:sxm@postgres:5432/sxm"
    redis_url: str = "redis://redis:6379/0"
    secret_key: str = "change-me-in-production"
    jwt_algorithm: str = "HS256"
    access_token_ttl_minutes: int = 480

    # --- Bootstrap admin ---
    admin_username: str = "admin"
    admin_password: str = "admin"

    # --- Confidence / lifecycle (C11, C14) ---
    confirm_threshold: int = 7
    gone_after_days: int = 14

    # --- Toggles (C9/C12) ---
    daily_snapshots: bool = False
    auto_probe_on_doubt: bool = False
    auto_probe_max_per_cycle: int = 25          # safety cap on auto-probes

    # --- Retention (open item section 13) ---
    observation_retention_days: int = 90        # purge raw observation payloads older than this

    # --- Connector mode ---
    connector_mode: str = "fixtures"            # fixtures | live

    # Tenable
    tenable_url: str = "https://cloud.tenable.com"
    tenable_access_key: str = ""
    tenable_secret_key: str = ""
    # Shadowserver
    shadowserver_url: str = "https://transform.shadowserver.org/api2/"
    shadowserver_api_key: str = ""
    shadowserver_secret: str = ""
    shadowserver_report_types: str = "scan_http,scan_https,scan_ssh,populate"  # csv
    # Shodan
    shodan_api_key: str = ""
    # dnsdumpster
    dnsdumpster_api_key: str = ""
    dnsdumpster_url: str = "https://api.dnsdumpster.com"
    # ELSA (roadmap)
    elsa_url: str = ""
    elsa_api_key: str = ""
    # SOCRadar (roadmap)
    socradar_url: str = "https://platform.socradar.com/api"
    socradar_api_key: str = ""

    # --- DNS resolution (discovery expansion) ---
    resolve_enumerated: bool = True

    # --- Alert channels: SMTP fallback config ---
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = "sxm@localhost"
    smtp_use_tls: bool = True

    # --- OIDC (C6) — disabled by default; local accounts remain primary ---
    oidc_enabled: bool = False
    oidc_issuer: str = ""
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    oidc_redirect_uri: str = ""
    oidc_scopes: str = "openid profile email"
    oidc_role_claim: str = "groups"
    oidc_role_map: str = ""                      # json: {"soc-admins":"admin"}
    oidc_default_role: str = "manager"

    # --- POC no-Docker mode ---
    serve_ui: bool = True                        # mount ui/ from the API process (single origin)

    # --- standalone scheduler (app.run_scheduler; replaces Celery beat) ---
    scheduler_run_on_start: bool = True          # run one full cycle immediately on launch
    scheduler_full_cycle_seconds: int = 86400    # ingest + reconcile (+ auto-probe)
    scheduler_snapshot_seconds: int = 604800     # trend snapshot cadence
    scheduler_snapshot_granularity: str = "weekly"
    scheduler_purge_seconds: int = 604800        # retention purge cadence


@lru_cache
def get_settings() -> Settings:
    return Settings()
