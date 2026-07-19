#!/usr/bin/env python3
"""
aisec.py — интерактивная обёртка над обоими контурами. Без внешних зависимостей.

Конфиг берётся из окружения (или флагов):
  AISEC_TOKEN     — сырой operator-токен (обязателен)
  AISEC_SOAR_URL  — по умолчанию http://127.0.0.1:8010
  AISEC_PENT_URL  — по умолчанию http://127.0.0.1:8020

Примеры:
  export AISEC_TOKEN=<operator-token>
  python3 aisec.py soar --id INC-42 --source EDR --title "Suspicious PS" --raw "host 10.0.4.17 ..."
  python3 aisec.py soar            # интерактивный ввод инцидента
  python3 aisec.py pentest         # пошаговый цикл plan → approve
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request
import urllib.error

SOAR_URL = os.environ.get("AISEC_SOAR_URL", "http://127.0.0.1:8010")
PENT_URL = os.environ.get("AISEC_PENT_URL", "http://127.0.0.1:8020")
TOKEN = os.environ.get("AISEC_TOKEN", "")

# --- цветной вывод severity в терминале ---
C = {"reset": "\033[0m", "dim": "\033[2m", "bold": "\033[1m",
     "info": "\033[36m", "low": "\033[32m", "medium": "\033[33m",
     "high": "\033[35m", "critical": "\033[31m", "ok": "\033[32m", "bad": "\033[31m"}


def sev(s: str) -> str:
    s = (s or "info").lower()
    return f"{C.get(s, '')}{s.upper()}{C['reset']}"


def _call(base: str, path: str, payload: dict | None = None, method: str = "POST") -> dict:
    if not TOKEN:
        sys.exit("Нет токена. Задайте AISEC_TOKEN=<operator-token>.")
    url = base + path
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"content-type": "application/json",
                                          "x-api-key": TOKEN})
    try:
        with urllib.request.urlopen(req, timeout=210) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        try:
            detail = json.loads(body).get("detail", body)
        except Exception:  # noqa: BLE001
            detail = body
        if e.code == 429:
            sys.exit("429 — слишком часто, подождите минуту.")
        if e.code in (401, 403):
            sys.exit(f"{e.code} — {detail}")
        sys.exit(f"HTTP {e.code}: {detail}")
    except urllib.error.URLError as e:
        sys.exit(f"Сервис недоступен ({base}): {e.reason}. Запущен ли контейнер?")


def _bullets(items, indent="    "):
    if not items:
        print(f"{indent}{C['dim']}—{C['reset']}")
        return
    for i in items:
        print(f"{indent}• {i}")


# ---------------- SOAR ----------------
def cmd_soar(args):
    inc = {
        "incident_id": args.id or input("Incident ID: ").strip(),
        "source": args.source or (input("Source [EDR/SIEM/Firewall]: ").strip() or "EDR"),
        "title": args.title or input("Title: ").strip(),
        "raw": args.raw or input("Raw (лог/описание): ").strip(),
        "enrich_external": args.enrich,
    }
    print(f"\n{C['dim']}→ анализирую инцидент…{C['reset']}")
    d = _call(SOAR_URL, "/v1/advise", inc)
    a = d.get("advice", {})
    print(f"\n{C['bold']}{a.get('summary','—')}{C['reset']}  [{sev(a.get('severity'))}]")
    print(f"{C['dim']}confidence: {a.get('confidence','—')} · route: {d.get('route')}"
          f"{' · masked: '+str(d.get('masked_terms')) if d.get('masked_terms') else ''}{C['reset']}")
    if a.get("mitre"):
        print(f"{C['dim']}MITRE:{C['reset']} " + ", ".join(a["mitre"]))
    print(f"\n{C['bold']}Немедленные действия:{C['reset']}");    _bullets(a.get("immediate_actions"))
    print(f"{C['bold']}Сдерживание:{C['reset']}");                _bullets(a.get("containment"))
    print(f"{C['bold']}Что проверить:{C['reset']}");              _bullets(a.get("investigation"))
    print(f"{C['bold']}Признаки ложного срабатывания:{C['reset']}"); _bullets(a.get("false_positive_signs"))
    if a.get("external_enrichment"):
        print(f"\n{C['bold']}Обогащение (внешний ИИ):{C['reset']}")
        print(json.dumps(a["external_enrichment"], ensure_ascii=False, indent=2))


# ---------------- PENTEST ----------------
def cmd_pentest(args):
    objective = args.objective or input("Objective (цель работ): ").strip()
    analyze_route = "external" if args.analyze_external else "local"
    session_id, last_output = None, None
    print(f"{C['dim']}Цикл: propose → approve. Ctrl+C для выхода.{C['reset']}\n")

    while True:
        req = {"session_id": session_id, "objective": objective, "last_output": last_output}
        print(f"{C['dim']}→ модель предлагает следующий шаг…{C['reset']}")
        d = _call(PENT_URL, "/v1/plan", req)
        session_id = d["session_id"]
        p = d.get("proposed", {})
        ok = d.get("scope_ok")
        mark = f"{C['ok']}✓ в scope{C['reset']}" if ok else f"{C['bad']}✗ вне scope{C['reset']}"
        print(f"\n{C['bold']}Шаг:{C['reset']} {p.get('tool','?')} → {C['bold']}{p.get('target','—')}{C['reset']}  [{mark}]")
        print(f"  {C['dim']}зачем:{C['reset']} {p.get('rationale','—')}")
        print(f"  {C['dim']}ожидаем:{C['reset']} {p.get('expected','—')}")

        if not ok:
            print(f"  {C['bad']}{'; '.join(d.get('problems', []))}{C['reset']}")
            if input("\nШаг вне scope. Запросить другой? [Y/n]: ").strip().lower() in ("", "y"):
                last_output = None
                continue
            break

        choice = input("\n[a] approve & run · [r] reject · [q] quit: ").strip().lower()
        if choice == "q":
            break
        if choice == "r":
            _call(PENT_URL, "/v1/approve", {"step_id": d["step_id"], "approved": False})
            print(f"{C['dim']}Шаг отклонён. Запрашиваю следующий…{C['reset']}\n")
            last_output = None
            continue

        print(f"{C['dim']}→ запускаю инструмент…{C['reset']}")
        res = _call(PENT_URL, "/v1/approve",
                    {"step_id": d["step_id"], "approved": True, "analyze_route": analyze_route})
        tr, an = res.get("tool_result", {}), res.get("analysis", {})
        print(f"\n{C['dim']}rc={tr.get('returncode')} · analyze={res.get('analyze_route')}"
              f"{' · masked='+str(res.get('masked_terms')) if res.get('masked_terms') else ''}{C['reset']}")
        out = (tr.get("stdout") or "").strip()
        if out:
            print(f"{C['dim']}--- вывод ---{C['reset']}")
            print(out[:4000])
        for f in an.get("findings", []):
            print(f"\n  [{sev(f.get('severity'))}] {C['bold']}{f.get('title','finding')}{C['reset']}")
            print(f"    evidence: {f.get('evidence','—')}")
            print(f"    fix:      {f.get('recommendation','—')}")
        if an.get("next_suggestion"):
            print(f"\n{C['dim']}next:{C['reset']} {an['next_suggestion']}")

        # вывод текущего шага подаётся в следующий /plan как контекст
        last_output = (tr.get("stdout", "") + "\n" + tr.get("stderr", "")).strip()
        if input(f"\n{C['bold']}Продолжить к следующему шагу? [Y/n]: {C['reset']}").strip().lower() not in ("", "y"):
            break

    print("Сессия завершена.")
    # Предлагаем сохранить отчёт по сессии
    if session_id:
        try:
            ans = input("Сохранить отчёт по сессии в .md? [Y/n]: ").strip().lower()
        except EOFError:
            ans = "n"
        if ans in ("", "y"):
            r = _call(PENT_URL, f"/v1/report/{session_id}/markdown?save=true",
                      payload=None, method="GET")
            md = r.get("markdown", "")
            fname = f"report_{session_id[:8]}.md"
            with open(fname, "w", encoding="utf-8") as fh:
                fh.write(md)
            saved = r.get("saved_to")
            print(f"Отчёт сохранён: {fname}" + (f" (и в контуре: {saved})" if saved else ""))


def main():
    ap = argparse.ArgumentParser(description="AI-SEC интерактивная обёртка")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("soar", help="Триаж инцидента")
    s.add_argument("--id"); s.add_argument("--source"); s.add_argument("--title")
    s.add_argument("--raw"); s.add_argument("--enrich", action="store_true",
                                            help="обогатить внешним ИИ (обезличенно)")
    s.set_defaults(func=cmd_soar)

    p = sub.add_parser("pentest", help="Пошаговый цикл plan→approve")
    p.add_argument("--objective")
    p.add_argument("--analyze-external", action="store_true",
                   help="разбирать вывод внешним ИИ (обезличенно)")
    p.set_defaults(func=cmd_pentest)

    args = ap.parse_args()
    try:
        args.func(args)
    except KeyboardInterrupt:
        print("\nПрервано.")


if __name__ == "__main__":
    main()
