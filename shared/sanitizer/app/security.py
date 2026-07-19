"""
Общие механизмы защиты для обоих контуров.

  - аутентификация по API-ключу + rate limiting
  - простая ролевая модель (viewer/operator/admin)
  - структурированный аудит событий (append-only)
  - заголовки безопасности, no-store
"""
from __future__ import annotations

import os
import time
import json
import hmac
import hashlib
from pathlib import Path
from typing import Optional

from fastapi import Header, HTTPException, Request
from starlette.middleware.base import BaseHTTPMiddleware


# --- секреты только из окружения / secrets manager ---
def get_secret(key: str) -> str:
    val = os.environ.get(key)
    if not val:
        raise RuntimeError(f"Required secret '{key}' not configured")
    return val


# --- разбор API-ключей вида "role:token", хэш сверяем константным временем ---
def _load_keys() -> dict[str, str]:
    # Формат API_KEYS: "admin:HASH,operator:HASH" (HASH = sha256 токена)
    raw = os.environ.get("API_KEYS", "")
    keys = {}
    for part in filter(None, (p.strip() for p in raw.split(","))):
        role, _, h = part.partition(":")
        if role and h:
            keys[h] = role
    return keys


_KEYS = _load_keys()


def authenticate(x_api_key: Optional[str] = Header(default=None)) -> str:
    """Возвращает роль субъекта или отклоняет запрос."""
    if not x_api_key:
        raise HTTPException(status_code=401, detail="API key required")
    h = hashlib.sha256(x_api_key.encode()).hexdigest()
    for known_h, role in _KEYS.items():
        if hmac.compare_digest(h, known_h):   # защита от timing attack
            return role
    raise HTTPException(status_code=403, detail="Invalid API key")


def require_role(role: str, allowed: set[str]):
    if role not in allowed:
        raise HTTPException(status_code=403, detail="Insufficient permissions")


# --- примитивный in-memory rate limiter (для прод — Redis) ---
_RL: dict[str, list[float]] = {}


def rate_limit(key: str, limit: int, window: int = 60):
    now = time.time()
    bucket = [t for t in _RL.get(key, []) if now - t < window]
    if len(bucket) >= limit:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    bucket.append(now)
    _RL[key] = bucket


# --- append-only журнал событий безопасности ---
_AUDIT_PATH = Path(os.environ.get("AUDIT_LOG", "/data/audit/security.log"))


def audit(event_type: str, subject: str, resource: str, result: str, **details):
    """Запись: время, субъект, объект, тип операции, результат."""
    _AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "ts": time.time(),
        "iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "event_type": event_type,
        "subject": subject,
        "resource": resource,
        "result": result,
        "details": details,
    }
    # append-only; в проде — пересылка в SIEM
    with _AUDIT_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


# --- заголовки безопасности ---
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers.update({
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Cache-Control": "no-store",
        })
        return response
