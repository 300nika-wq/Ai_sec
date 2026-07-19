"""
Контур 1 — SOAR Incident Advisor.

Назначение: получает событие/инцидент (алерт SIEM, лог, кейс),
возвращает структурированную рекомендацию аналитику L1/L2:
  - краткая оценка (что происходит),
  - критичность,
  - шаги реагирования (containment / eradication / recovery),
  - что проверить дополнительно.

Данные инцидента (IP, хосты, ФИО в логах) по умолчанию обрабатываются
ЛОКАЛЬНОЙ моделью. Внешний ИИ используется только для обогащения
(например, разбор редкой TTP по MITRE) и только с обезличенными данными —
через тот же санитайзер-роутер.
"""
from __future__ import annotations

import os
import json
import httpx
from fastapi import FastAPI, Depends
from pydantic import BaseModel

from app_security import authenticate, require_role, audit, SecurityHeadersMiddleware

app = FastAPI(title="SOAR Incident Advisor", docs_url=None, redoc_url=None)
app.add_middleware(SecurityHeadersMiddleware)
# CORS: разрешаем только локальный веб-интерфейс (localhost на любом порту)
from fastapi.middleware.cors import CORSMiddleware
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"http://(localhost|127\.0\.0\.1)(:\d+)?",
    allow_methods=["GET", "POST"],
    allow_headers=["x-api-key", "content-type"],
)

SANITIZER_URL = os.environ.get("SANITIZER_URL", "http://sanitizer:8000")
# Маршрут разбора инцидента по умолчанию: local | external (внешний ИИ через
# санитайзер). external сработает только при ALLOW_EXTERNAL=true в санитайзере.
DEFAULT_ROUTE = os.environ.get("DEFAULT_ROUTE", "local").lower()

SYSTEM_PROMPT = """Ты — старший аналитик SOC. По входному инциденту дай рекомендацию
СТРОГО в JSON со схемой:
{
  "summary": "1-2 предложения: что происходит",
  "severity": "info|low|medium|high|critical",
  "confidence": "low|medium|high",
  "mitre": ["Txxxx: техника"],
  "immediate_actions": ["шаг 1", "шаг 2"],
  "investigation": ["что дополнительно проверить"],
  "containment": ["меры сдерживания"],
  "false_positive_signs": ["признаки ложного срабатывания"]
}
Не выдумывай IP/хосты, работай только с данными инцидента. Только JSON, без пояснений."""


class Incident(BaseModel):
    incident_id: str
    source: str                 # "SIEM" | "EDR" | "firewall" | ...
    title: str
    raw: str                    # сырой лог/описание (может содержать IP/ПДн)
    enrich_external: bool = False   # разрешить обогащение внешним ИИ (обезличенно)


class Advice(BaseModel):
    incident_id: str
    route: str
    advice: dict
    masked_terms: int


async def _ask(prompt: str, system: str, route: str, sid: str) -> dict:
    """Обращение к санитайзер-роутеру. Ключ сервиса — из окружения."""
    headers = {"x-api-key": os.environ["SANITIZER_SERVICE_KEY"]}
    body = {"prompt": prompt, "system": system, "route": route,
            "session_id": sid, "temperature": 0.1}
    async with httpx.AsyncClient(timeout=200) as c:
        r = await c.post(f"{SANITIZER_URL}/v1/complete", headers=headers, json=body)
        r.raise_for_status()
        return r.json()


def _parse_json(text: str) -> dict:
    text = text.strip().removeprefix("```json").removeprefix("```").removesuffix("```")
    try:
        return json.loads(text)
    except Exception:  # noqa: BLE001
        return {"summary": text[:500], "severity": "medium",
                "_parse_error": "model did not return valid JSON"}


@app.post("/v1/advise", response_model=Advice)
async def advise(inc: Incident, role: str = Depends(authenticate)):
    require_role(role, {"operator", "admin"})
    # фиксируем инцидент в аудите ДО обработки
    audit("incident_received", role, inc.incident_id, "processing",
          source=inc.source, title=inc.title)

    # Разбор инцидента: по умолчанию локально; при DEFAULT_ROUTE=external —
    # через санитайзер во внешний ИИ (данные обезличиваются перед отправкой).
    prompt = f"ИНЦИДЕНТ [{inc.source}] {inc.title}\n\nДАННЫЕ:\n{inc.raw}"
    resp = await _ask(prompt, SYSTEM_PROMPT, DEFAULT_ROUTE, inc.incident_id)
    advice = _parse_json(resp["text"])
    route = resp.get("route", DEFAULT_ROUTE)
    masked = resp.get("masked_terms", 0)

    # Опциональное обогащение внешним ИИ — ТОЛЬКО обезличенно.
    # Санитайзер сам замаскирует IP/ПДн; сюда прилетит уже размаскированный ответ.
    if inc.enrich_external:
        enrich_prompt = (
            f"Разбери технику атаки по MITRE ATT&CK для инцидента:\n"
            f"{inc.title}\n{inc.raw}\n"
            f"Дай TTP, типовые способы обнаружения и меры. JSON: "
            f'{{"mitre":[...],"detection":[...],"mitigation":[...]}}'
        )
        ext = await _ask(enrich_prompt, "Ты эксперт по MITRE ATT&CK. Только JSON.",
                         "external", inc.incident_id)
        enrichment = _parse_json(ext["text"])
        advice["external_enrichment"] = enrichment
        route = f"local+external"
        masked = ext.get("masked_terms", 0)

    audit("incident_advised", role, inc.incident_id, "done",
          severity=advice.get("severity"), route=route, masked=masked)
    return Advice(incident_id=inc.incident_id, route=route,
                  advice=advice, masked_terms=masked)


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}
