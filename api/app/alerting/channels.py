"""Alert channels. All functional: console, webhook, email (SMTP), telegram."""
from __future__ import annotations

import json
import logging
import smtplib
from email.message import EmailMessage

import httpx

from ..config import get_settings
from ..models import AlertChannel, ChannelKind

log = logging.getLogger("sxm.alerts")
settings = get_settings()


def _fmt(payload: dict) -> str:
    return (f"[SXM] {payload['event'].upper()} {payload['endpoint']} "
            f"({payload.get('service_type') or '?'}, {payload.get('attribution')}, "
            f"score={payload['confidence']}) at {payload['at']}")


def deliver(channel: AlertChannel, payload: dict) -> None:
    """Raise on failure so the caller records status=failed."""
    cfg = channel.config or {}

    if channel.kind == ChannelKind.console:
        log.warning("ALERT %s", json.dumps(payload))

    elif channel.kind == ChannelKind.webhook:
        url = cfg.get("url")
        if not url:
            raise ValueError("webhook channel missing 'url'")
        with httpx.Client(timeout=10) as c:
            c.post(url, json=payload).raise_for_status()

    elif channel.kind == ChannelKind.email:
        host = cfg.get("host") or settings.smtp_host
        if not host:
            raise ValueError("no SMTP host configured")
        recipients = cfg.get("to") or []
        if isinstance(recipients, str):
            recipients = [recipients]
        if not recipients:
            raise ValueError("email channel missing 'to'")
        msg = EmailMessage()
        msg["Subject"] = f"[SXM] {payload['event']} {payload['endpoint']}"
        msg["From"] = cfg.get("from") or settings.smtp_from
        msg["To"] = ", ".join(recipients)
        msg.set_content(_fmt(payload) + "\n\n" + json.dumps(payload, indent=2))
        port = int(cfg.get("port") or settings.smtp_port)
        with smtplib.SMTP(host, port, timeout=15) as s:
            if cfg.get("use_tls", settings.smtp_use_tls):
                s.starttls()
            user = cfg.get("user") or settings.smtp_user
            pw = cfg.get("password") or settings.smtp_password
            if user:
                s.login(user, pw)
            s.send_message(msg)

    elif channel.kind == ChannelKind.telegram:
        token = cfg.get("bot_token")
        chat_id = cfg.get("chat_id")
        if not token or not chat_id:
            raise ValueError("telegram channel needs 'bot_token' and 'chat_id'")
        with httpx.Client(timeout=10) as c:
            c.post(f"https://api.telegram.org/bot{token}/sendMessage",
                   json={"chat_id": chat_id, "text": _fmt(payload)}).raise_for_status()

    else:
        raise ValueError(f"unknown channel kind {channel.kind}")
