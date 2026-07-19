"""
Санитайзер-роутер к LLM — общее ядро обоих контуров.

Маршруты:
  POST /v1/complete   — единая точка. Поле "route": "local" | "external".
    - local:    запрос уходит в Ollama как есть (данные не покидают контур).
    - external: запрос МАСКИРУЕТСЯ, уходит в коммерческий API (ZDR-тариф),
                ответ размаскировывается обратно и возвращается аналитику.

Ключевой инвариант: реальные IP/ПДн/секреты НИКОГДА не уходят
на внешний маршрут. Наружу — только плейсхолдеры.
"""
from __future__ import annotations

import os
import re
import uuid
import httpx
from fastapi import FastAPI, Depends, Request, HTTPException
from pydantic import BaseModel

from .masking import MaskVault, sanitize, desanitize, vault_fingerprint
from .security import (
    authenticate, require_role, rate_limit, audit,
    get_secret, SecurityHeadersMiddleware,
)

app = FastAPI(title="AI-SEC Sanitizer Router", docs_url=None, redoc_url=None)
app.add_middleware(SecurityHeadersMiddleware)

# Изменяемая в рантайме конфигурация модели (инициализируется из окружения).
# Правится через PUT /v1/config (например, из веб-панели) — можно указать адрес
# другого Ollama, сменить модель или внешнего провайдера без пересборки.
# Секреты (EXTERNAL_API_KEY, YANDEX_FOLDER_ID) сюда НЕ входят — только из env.
CONFIG = {
    "ollama_url": os.environ.get("OLLAMA_URL", "http://ollama:11434").rstrip("/"),
    "local_model": os.environ.get("LOCAL_MODEL", "qwen2.5:32b"),
    # EXTERNAL_PROVIDER: anthropic | yandex | openai (Алиса/YandexGPT -> yandex).
    "provider": os.environ.get("EXTERNAL_PROVIDER", "anthropic").lower(),
    "external_url": os.environ.get("EXTERNAL_URL", "").rstrip("/"),
    "external_model": os.environ.get("EXTERNAL_MODEL", "claude-sonnet-4-6"),
}
YANDEX_FOLDER_ID = os.environ.get("YANDEX_FOLDER_ID", "")   # для yandex: id каталога
# Жёсткий рубильник наружу — ТОЛЬКО из env (в вебе read-only, менять нельзя).
ALLOW_EXTERNAL = os.environ.get("ALLOW_EXTERNAL", "false").lower() == "true"

_PROVIDERS = {"anthropic", "yandex", "openai"}
_MODEL_RE = re.compile(r"^[A-Za-z0-9_./:\-]{1,120}$")


def _valid_url(u: str) -> bool:
    from urllib.parse import urlparse
    try:
        p = urlparse(u)
    except Exception:  # noqa: BLE001
        return False
    return p.scheme in ("http", "https") and bool(p.netloc)


def _public_config() -> dict:
    """Текущий конфиг для отдачи наружу — без секретов, с флагами наличия ключей."""
    return {
        **CONFIG,
        "allow_external": ALLOW_EXTERNAL,           # read-only (из env)
        "external_api_key_set": bool(os.environ.get("EXTERNAL_API_KEY")),
        "yandex_folder_set": bool(YANDEX_FOLDER_ID),
    }


class CompleteRequest(BaseModel):
    prompt: str
    system: str | None = None
    route: str = "local"          # "local" | "external"
    session_id: str | None = None
    temperature: float = 0.2


class CompleteResponse(BaseModel):
    session_id: str
    route: str
    text: str
    masked_terms: int             # сколько сущностей заменено (для аудита)
    vault_fingerprint: str | None = None


async def _call_local(prompt: str, system: str | None, temp: float) -> str:
    payload = {
        "model": CONFIG["local_model"],
        "prompt": prompt,
        "system": system or "",
        "stream": False,
        "options": {"temperature": temp},
    }
    async with httpx.AsyncClient(timeout=180) as c:
        r = await c.post(f"{CONFIG['ollama_url']}/api/generate", json=payload)
        r.raise_for_status()
        return r.json().get("response", "")


async def _call_external(prompt: str, system: str | None, temp: float) -> str:
    """Диспетчер внешнего провайдера. На вход приходит УЖЕ обезличенный текст."""
    if CONFIG["provider"] == "yandex":
        return await _call_yandex(prompt, system, temp)
    if CONFIG["provider"] == "openai":
        return await _call_openai(prompt, system, temp)
    return await _call_anthropic(prompt, system, temp)


async def _call_anthropic(prompt: str, system: str | None, temp: float) -> str:
    api_key = get_secret("EXTERNAL_API_KEY")
    url = (CONFIG["external_url"] or "https://api.anthropic.com").rstrip("/")
    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }
    body = {
        "model": CONFIG["external_model"],
        "max_tokens": 2048,
        "temperature": temp,
        "system": system or "",
        "messages": [{"role": "user", "content": prompt}],
    }
    async with httpx.AsyncClient(timeout=120) as c:
        r = await c.post(f"{url}/v1/messages", headers=headers, json=body)
        r.raise_for_status()
        data = r.json()
        return "".join(b.get("text", "") for b in data.get("content", []))


async def _call_yandex(prompt: str, system: str | None, temp: float) -> str:
    """YandexGPT (модель «Алисы») через Yandex Cloud Foundation Models.
    Auth: Api-Key от сервисного аккаунта + x-folder-id. Данные уже обезличены."""
    api_key = get_secret("EXTERNAL_API_KEY")
    folder = YANDEX_FOLDER_ID or get_secret("YANDEX_FOLDER_ID")
    url = CONFIG["external_url"] or "https://llm.api.cloud.yandex.net/foundationModels/v1/completion"
    ext_model = CONFIG["external_model"]
    # modelUri: либо задан целиком (gpt://...), либо собираем из folder+модели.
    model_uri = (ext_model if ext_model.startswith("gpt://")
                 else f"gpt://{folder}/{ext_model}")
    headers = {"Authorization": f"Api-Key {api_key}",
               "x-folder-id": folder, "content-type": "application/json"}
    messages = []
    if system:
        messages.append({"role": "system", "text": system})
    messages.append({"role": "user", "text": prompt})
    body = {"modelUri": model_uri,
            "completionOptions": {"stream": False, "temperature": temp, "maxTokens": "2000"},
            "messages": messages}
    async with httpx.AsyncClient(timeout=120) as c:
        r = await c.post(url, headers=headers, json=body)
        r.raise_for_status()
        data = r.json()
        return data["result"]["alternatives"][0]["message"]["text"]


async def _call_openai(prompt: str, system: str | None, temp: float) -> str:
    """OpenAI-совместимый эндпоинт (в т.ч. многие RU-прокси). Данные уже обезличены."""
    api_key = get_secret("EXTERNAL_API_KEY")
    url = (CONFIG["external_url"] or "https://api.openai.com").rstrip("/")
    headers = {"Authorization": f"Bearer {api_key}", "content-type": "application/json"}
    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})
    body = {"model": CONFIG["external_model"], "temperature": temp, "max_tokens": 2048,
            "messages": messages}
    async with httpx.AsyncClient(timeout=120) as c:
        r = await c.post(f"{url}/v1/chat/completions", headers=headers, json=body)
        r.raise_for_status()
        data = r.json()
        return data["choices"][0]["message"]["content"]


@app.post("/v1/complete", response_model=CompleteResponse)
async def complete(
    req: CompleteRequest,
    request: Request,
    role: str = Depends(authenticate),
):
    require_role(role, {"operator", "admin"})
    rate_limit(f"complete:{role}", limit=60, window=60)
    sid = req.session_id or str(uuid.uuid4())

    if req.route == "external":
        if not ALLOW_EXTERNAL:
            audit("llm_external_blocked", role, "sanitizer", "blocked", session_id=sid)
            return CompleteResponse(
                session_id=sid, route="blocked",
                text="Внешний маршрут запрещён политикой контура (ALLOW_EXTERNAL=false).",
                masked_terms=0,
            )
        # МАСКИРУЕМ вход перед выходом наружу
        vault = MaskVault(session_id=sid)
        safe_prompt, vault = sanitize(req.prompt, vault)
        safe_system, vault = sanitize(req.system or "", vault)
        audit("llm_external_call", role, "external_api", "sent",
              session_id=sid, masked=len(vault.forward),
              fp=vault_fingerprint(vault))

        raw = await _call_external(safe_prompt, safe_system, req.temperature)
        # РАЗМАСКИРУЕМ ответ обратно для аналитика
        final = desanitize(raw, vault)
        return CompleteResponse(
            session_id=sid, route="external", text=final,
            masked_terms=len(vault.forward),
            vault_fingerprint=vault_fingerprint(vault),
        )

    # local route — данные не покидают контур, маскировка не нужна
    audit("llm_local_call", role, CONFIG["local_model"], "sent", session_id=sid)
    text = await _call_local(req.prompt, req.system, req.temperature)
    return CompleteResponse(session_id=sid, route="local", text=text, masked_terms=0)


# ---------------- Конфигурация модели (для веб-панели) ----------------
class ConfigUpdate(BaseModel):
    ollama_url: str | None = None
    local_model: str | None = None
    provider: str | None = None
    external_url: str | None = None
    external_model: str | None = None


@app.get("/v1/config")
async def get_config(role: str = Depends(authenticate)):
    require_role(role, {"operator", "admin"})
    return _public_config()


@app.put("/v1/config")
async def set_config(req: ConfigUpdate, role: str = Depends(authenticate)):
    """Изменение параметров модели в рантайме (например, адрес другого Ollama).
    Секреты и ALLOW_EXTERNAL здесь не меняются. Перезапуск sanitizer вернёт к env."""
    require_role(role, {"operator", "admin"})
    changes: dict = {}

    if req.ollama_url is not None:
        u = req.ollama_url.strip().rstrip("/")
        if not _valid_url(u):
            raise HTTPException(status_code=400, detail="ollama_url должен быть http(s)://host[:port]")
        CONFIG["ollama_url"] = u
        changes["ollama_url"] = u

    if req.local_model is not None:
        m = req.local_model.strip()
        if not _MODEL_RE.match(m):
            raise HTTPException(status_code=400, detail="Недопустимое имя модели")
        CONFIG["local_model"] = m
        changes["local_model"] = m

    if req.provider is not None:
        p = req.provider.strip().lower()
        if p not in _PROVIDERS:
            raise HTTPException(status_code=400, detail=f"provider ∈ {sorted(_PROVIDERS)}")
        CONFIG["provider"] = p
        changes["provider"] = p

    if req.external_url is not None:
        u = req.external_url.strip().rstrip("/")
        if u and not _valid_url(u):
            raise HTTPException(status_code=400, detail="external_url должен быть http(s)://… или пустым")
        CONFIG["external_url"] = u
        changes["external_url"] = u

    if req.external_model is not None:
        m = req.external_model.strip()
        if m and not _MODEL_RE.match(m):
            raise HTTPException(status_code=400, detail="Недопустимое имя внешней модели")
        CONFIG["external_model"] = m
        changes["external_model"] = m

    if not changes:
        raise HTTPException(status_code=400, detail="Не передано ни одного поля")

    audit("llm_config_updated", role, "sanitizer", "done", changes=changes)
    return {"config": _public_config(), "changed": changes,
            "note": "Изменено в памяти. Перезапуск sanitizer вернёт к .env."}


@app.get("/healthz")
async def healthz():
    return {"status": "ok", "external_allowed": ALLOW_EXTERNAL,
            "provider": CONFIG["provider"] if ALLOW_EXTERNAL else None,
            "external_model": CONFIG["external_model"] if ALLOW_EXTERNAL else None,
            "local_model": CONFIG["local_model"], "ollama_url": CONFIG["ollama_url"]}
