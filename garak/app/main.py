"""
garak Runner — тонкая обёртка-API над LLM-сканером garak (NVIDIA) + веб-панель.

Зачем отдельно: garak тяжёлый (torch/transformers) и по духу — «ручной запуск вне
оркестратора». Здесь он живёт в своём контейнере/сети, а панель даёт настроить и
запустить скан по мишеням стенда и посмотреть pass-rate по классам атак.

Предохранители те же, что и в остальном стенде:
  - аутентификация по API-ключу (operator/admin), аудит, rate-limit, заголовки;
  - allowlist хостов (GARAK_ALLOWED_HOSTS) — из браузера нельзя натравить garak на
    произвольный URL;
  - запуск строго списком аргументов (shell=False), probe-имена валидируются.
"""
from __future__ import annotations

import os
import re
import json
import uuid
import shutil
import asyncio
import pathlib
from urllib.parse import urlparse

from fastapi import FastAPI, Depends, HTTPException
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from app_security import (authenticate, require_role, rate_limit, audit,
                          SecurityHeadersMiddleware)

app = FastAPI(title="AI-SEC garak Runner", docs_url=None, redoc_url=None)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"http://(localhost|127\.0\.0\.1)(:\d+)?",
    allow_methods=["GET", "POST"],
    allow_headers=["x-api-key", "content-type"],
)

REPORTS_DIR = pathlib.Path(os.environ.get("GARAK_REPORTS_DIR", "/data/garak"))
REPORTS_DIR.mkdir(parents=True, exist_ok=True)
INDEX_HTML = pathlib.Path(__file__).parent / "index.html"
GARAK_BIN = shutil.which("garak") or "garak"

ALLOWED_HOSTS = {h.strip().lower() for h in os.environ.get(
    "GARAK_ALLOWED_HOSTS", "vulnllm,ragapp,ollama,127.0.0.1,localhost").split(",") if h.strip()}

_PROBE_RE = re.compile(r"^[A-Za-z0-9_.]{1,64}$")

# Кураторский набор probe'ов с человекочитаемыми названиями (для панели).
CURATED_PROBES = [
    {"id": "promptinject", "name": "Prompt Injection", "owasp": "LLM01",
     "desc": "Прямая инъекция инструкций в промпт."},
    {"id": "dan", "name": "Jailbreak (DAN)", "owasp": "LLM01",
     "desc": "Десятки jailbreak-персон, обходящих ограничения."},
    {"id": "encoding", "name": "Encoding bypass", "owasp": "LLM01",
     "desc": "Обход фильтров через Base64/ROT13/hex."},
    {"id": "latentinjection", "name": "Indirect / Latent injection", "owasp": "LLM01",
     "desc": "Непрямая инъекция через контекст/документ (как RAG)."},
    {"id": "leakreplay", "name": "Training data leak", "owasp": "LLM02",
     "desc": "Утечка/повтор обучающих данных."},
    {"id": "xss", "name": "XSS in output", "owasp": "LLM05",
     "desc": "Генерация XSS-нагрузки в ответе модели."},
    {"id": "malwaregen", "name": "Malware generation", "owasp": "LLM06",
     "desc": "Попытки заставить писать вредоносный код."},
    {"id": "packagehallucination", "name": "Package hallucination", "owasp": "LLM03",
     "desc": "Галлюцинация несуществующих пакетов (supply-chain)."},
    {"id": "realtoxicityprompts", "name": "Toxicity", "owasp": "LLM09",
     "desc": "Токсичный/небезопасный контент."},
    {"id": "glitch", "name": "Glitch tokens", "owasp": "LLM09",
     "desc": "Glitch-токены, ломающие поведение модели."},
]

# Пресеты мишеней стенда: как garak к ним подключается.
PRESETS = {
    "vulnllm": {"label": "Vulnerable LLM App (vulnllm)", "target_type": "rest",
                "uri": "http://vulnllm:8000/chat", "response_field": "reply"},
    "ragapp": {"label": "Vulnerable RAG App (ragapp)", "target_type": "rest",
               "uri": "http://ragapp:8000/chat", "response_field": "reply"},
    "ollama": {"label": "Локальная модель напрямую (ollama)", "target_type": "ollama",
               "uri": "", "response_field": ""},
}

# Реестр сканов (in-memory — как и остальной стенд; для прод — БД).
_SCANS: dict[str, dict] = {}


class ScanRequest(BaseModel):
    target_type: str = "rest"          # rest | ollama
    uri: str | None = None             # для rest: полный URL /chat
    model: str | None = None           # для ollama: имя модели; для rest — метка
    response_field: str = "reply"      # поле ответа (rest); новый garak ждёт $.reply
    probes: list[str] = []
    generations: int = 5               # сколько попыток на каждый probe


def _check_uri(uri: str) -> str:
    p = urlparse(uri or "")
    if p.scheme not in ("http", "https") or not p.hostname:
        raise HTTPException(status_code=400, detail="uri должен быть http(s)://host…")
    if p.hostname.lower() not in ALLOWED_HOSTS:
        raise HTTPException(status_code=403,
                            detail=f"host '{p.hostname}' не в GARAK_ALLOWED_HOSTS")
    return uri


def _clean_probes(probes: list[str]) -> list[str]:
    out = []
    for p in probes:
        p = str(p).strip()
        if not p:
            continue
        if not _PROBE_RE.match(p):
            raise HTTPException(status_code=400, detail=f"Недопустимое имя probe: {p!r}")
        out.append(p)
    return out or ["promptinject"]


def _build_cmd(req: ScanRequest, run_dir: pathlib.Path) -> list[str]:
    """Формирует команду garak. Флаги централизованы здесь — при иной версии garak
    правится в одном месте."""
    probes = ",".join(_clean_probes(req.probes))
    gens = max(1, min(int(req.generations or 5), 50))
    prefix = str(run_dir / "scan")
    if req.target_type == "ollama":
        model = (req.model or "").strip()
        if not re.match(r"^[A-Za-z0-9_.:\-/]{1,120}$", model):
            raise HTTPException(status_code=400, detail="Укажите корректное имя модели ollama")
        return [GARAK_BIN, "--model_type", "ollama", "--model_name", model,
                "--probes", probes, "--generations", str(gens),
                "--report_prefix", prefix]
    # rest — пишем конфиг генератора
    _check_uri(req.uri or "")
    rest_cfg = {"rest": {"RestGenerator": {
        "name": (req.model or "lab-target")[:64],
        "uri": req.uri,
        "method": "post",
        "headers": {"Content-Type": "application/json"},
        "req_template_json_object": {"message": "$INPUT"},
        "response_json": True,
        "response_json_field": req.response_field or "reply",
    }}}
    cfg_path = run_dir / "rest.json"
    cfg_path.write_text(json.dumps(rest_cfg, ensure_ascii=False), encoding="utf-8")
    return [GARAK_BIN, "--model_type", "rest", "--generator_option_file", str(cfg_path),
            "--probes", probes, "--generations", str(gens),
            "--report_prefix", prefix]


def _parse_report(run_dir: pathlib.Path) -> list[dict]:
    """Толерантный разбор garak *.report.jsonl -> список {probe,detector,passed,total,rate}.
    Схема между версиями меняется, поэтому парсим защитно; сырой отчёт всегда доступен."""
    results: list[dict] = []
    files = sorted(run_dir.glob("*report.jsonl"))
    if not files:
        return results
    for line in files[-1].read_text(encoding="utf-8", errors="ignore").splitlines():
        try:
            rec = json.loads(line)
        except Exception:  # noqa: BLE001
            continue
        if not isinstance(rec, dict):
            continue
        if rec.get("entry_type") in ("eval", "evaluation") or ("passed" in rec and "total" in rec):
            total = rec.get("total") or 0
            passed = rec.get("passed", 0)
            rate = round(100.0 * passed / total, 1) if total else None
            results.append({
                "probe": rec.get("probe", rec.get("probe_name", "")),
                "detector": rec.get("detector", rec.get("detector_name", "")),
                "passed": passed, "total": total, "pass_rate": rate,
            })
    return results


async def _launch(sid: str) -> None:
    rec = _SCANS[sid]
    run_dir = pathlib.Path(rec["dir"])
    log_path = run_dir / "run.log"
    try:
        with open(log_path, "wb") as logf:
            proc = await asyncio.create_subprocess_exec(
                *rec["cmd"], stdout=logf, stderr=logf, cwd=str(run_dir))
            rec["status"] = "running"
            rc = await proc.wait()
        rec["returncode"] = rc
        rec["summary"] = _parse_report(run_dir)
        rec["status"] = "done" if rc == 0 else "failed"
    except Exception as e:  # noqa: BLE001
        rec["status"] = "failed"
        rec["error"] = str(e)
    audit("garak_scan_finished", rec.get("role", "?"), rec.get("target", ""),
          rec["status"], scan_id=sid, rc=rec.get("returncode"))


@app.get("/")
async def index():
    return FileResponse(str(INDEX_HTML))


@app.get("/v1/meta")
async def meta(role: str = Depends(authenticate)):
    return {"presets": PRESETS, "probes": CURATED_PROBES,
            "allowed_hosts": sorted(ALLOWED_HOSTS),
            "garak_installed": shutil.which("garak") is not None}


@app.post("/v1/scan")
async def start_scan(req: ScanRequest, role: str = Depends(authenticate)):
    require_role(role, {"operator", "admin"})
    rate_limit(f"garak:{role}", limit=20, window=60)
    if shutil.which("garak") is None:
        raise HTTPException(status_code=503, detail="garak не установлен в образе")
    sid = uuid.uuid4().hex[:12]
    run_dir = REPORTS_DIR / sid
    run_dir.mkdir(parents=True, exist_ok=True)
    cmd = _build_cmd(req, run_dir)              # валидация внутри
    target = req.uri or f"ollama:{req.model}"
    _SCANS[sid] = {"id": sid, "dir": str(run_dir), "cmd": cmd, "status": "queued",
                   "target": target, "probes": _clean_probes(req.probes),
                   "role": role, "returncode": None, "summary": []}
    audit("garak_scan_started", role, target, "running", scan_id=sid,
          probes=_SCANS[sid]["probes"])
    asyncio.create_task(_launch(sid))
    return {"scan_id": sid, "status": "queued", "target": target}


def _scan_view(rec: dict) -> dict:
    return {k: rec[k] for k in ("id", "status", "target", "probes", "returncode", "summary")
            if k in rec} | ({"error": rec["error"]} if rec.get("error") else {})


@app.get("/v1/scans")
async def list_scans(role: str = Depends(authenticate)):
    return {"scans": [_scan_view(r) for r in
                      sorted(_SCANS.values(), key=lambda x: x["id"])][::-1]}


@app.get("/v1/scan/{sid}")
async def scan_status(sid: str, role: str = Depends(authenticate)):
    rec = _SCANS.get(sid)
    if not rec:
        raise HTTPException(status_code=404, detail="scan не найден")
    return _scan_view(rec)


@app.get("/v1/scan/{sid}/log")
async def scan_log(sid: str, tail: int = 200, role: str = Depends(authenticate)):
    rec = _SCANS.get(sid)
    if not rec:
        raise HTTPException(status_code=404, detail="scan не найден")
    p = pathlib.Path(rec["dir"]) / "run.log"
    if not p.exists():
        return {"log": ""}
    lines = p.read_text(encoding="utf-8", errors="ignore").splitlines()
    return {"log": "\n".join(lines[-max(1, min(tail, 2000)):])}


@app.get("/healthz")
async def healthz():
    return {"status": "ok", "garak_installed": shutil.which("garak") is not None,
            "allowed_hosts": sorted(ALLOWED_HOSTS)}
