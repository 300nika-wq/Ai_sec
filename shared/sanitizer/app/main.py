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
import uuid
import httpx
from fastapi import FastAPI, Depends, Request
from pydantic import BaseModel

from .masking import MaskVault, sanitize, desanitize, vault_fingerprint
from .security import (
    authenticate, require_role, rate_limit, audit,
    get_secret, SecurityHeadersMiddleware,
)

app = FastAPI(title="AI-SEC Sanitizer Router", docs_url=None, redoc_url=None)
app.add_middleware(SecurityHeadersMiddleware)

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://ollama:11434")
LOCAL_MODEL = os.environ.get("LOCAL_MODEL", "qwen2.5:32b")

# Внешний провайдер. Тариф обязан быть с Zero-Data-Retention и opt-out обучения.
# EXTERNAL_PROVIDER: anthropic | yandex | openai (Алиса/YandexGPT -> yandex).
EXTERNAL_PROVIDER = os.environ.get("EXTERNAL_PROVIDER", "anthropic").lower()
EXTERNAL_URL = os.environ.get("EXTERNAL_URL", "")
EXTERNAL_MODEL = os.environ.get("EXTERNAL_MODEL", "claude-sonnet-4-6")
YANDEX_FOLDER_ID = os.environ.get("YANDEX_FOLDER_ID", "")   # для yandex: id каталога
# Разрешён ли внешний маршрут вообще (жёсткий рубильник наружу).
ALLOW_EXTERNAL = os.environ.get("ALLOW_EXTERNAL", "false").lower() == "true"


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
        "model": LOCAL_MODEL,
        "prompt": prompt,
        "system": system or "",
        "stream": False,
        "options": {"temperature": temp},
    }
    async with httpx.AsyncClient(timeout=180) as c:
        r = await c.post(f"{OLLAMA_URL}/api/generate", json=payload)
        r.raise_for_status()
        return r.json().get("response", "")


async def _call_external(prompt: str, system: str | None, temp: float) -> str:
    """Диспетчер внешнего провайдера. На вход приходит УЖЕ обезличенный текст."""
    if EXTERNAL_PROVIDER == "yandex":
        return await _call_yandex(prompt, system, temp)
    if EXTERNAL_PROVIDER == "openai":
        return await _call_openai(prompt, system, temp)
    return await _call_anthropic(prompt, system, temp)


async def _call_anthropic(prompt: str, system: str | None, temp: float) -> str:
    api_key = get_secret("EXTERNAL_API_KEY")
    url = (EXTERNAL_URL or "https://api.anthropic.com").rstrip("/")
    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }
    body = {
        "model": EXTERNAL_MODEL,
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
    url = EXTERNAL_URL or "https://llm.api.cloud.yandex.net/foundationModels/v1/completion"
    # modelUri: либо задан целиком (gpt://...), либо собираем из folder+модели.
    model_uri = (EXTERNAL_MODEL if EXTERNAL_MODEL.startswith("gpt://")
                 else f"gpt://{folder}/{EXTERNAL_MODEL}")
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
    url = (EXTERNAL_URL or "https://api.openai.com").rstrip("/")
    headers = {"Authorization": f"Bearer {api_key}", "content-type": "application/json"}
    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})
    body = {"model": EXTERNAL_MODEL, "temperature": temp, "max_tokens": 2048,
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
        if not ALLOW_EXTERNAL or not EXTERNAL_URL:
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
    audit("llm_local_call", role, LOCAL_MODEL, "sent", session_id=sid)
    text = await _call_local(req.prompt, req.system, req.temperature)
    return CompleteResponse(session_id=sid, route="local", text=text, masked_terms=0)


@app.get("/healthz")
async def healthz():
    return {"status": "ok", "external_allowed": ALLOW_EXTERNAL,
            "provider": EXTERNAL_PROVIDER if ALLOW_EXTERNAL else None,
            "external_model": EXTERNAL_MODEL if ALLOW_EXTERNAL else None}
