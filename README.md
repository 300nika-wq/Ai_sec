# AI-SEC Stack — два контура ИИ для ИБ

Два независимых профиля с общим ядром-санитайзером.

| Контур | Что делает | Внешний ИИ |
|---|---|---|
| **1. SOAR** (`docker-compose.soar.yml`) | По инциденту (SIEM/EDR/FW) даёт структурированную рекомендацию по реагированию | По умолчанию **выкл**; при `enrich_external` — только обезличенно |
| **2. Pentest / IB-специалист** (`docker-compose.pentest.yml`) | Ведёт авторизованный внешний пентест: предлагает шаг → человек подтверждает → запуск стандартного сканера → анализ вывода | По умолчанию **выкл**; анализ вывода можно вести обезличенно |

## Архитектура

```
[аналитик] → SOAR / Pentest API → [Санитайзер-роутер] ─┬─ route=local    → Ollama (данные не выходят из контура)
                                                        └─ route=external → маскировка → Внешний ИИ (ZDR) → размаскировка
```

**Главный инвариант:** реальные IP, ПДн и секреты никогда не уходят на внешний
маршрут. Наружу — только плейсхолдеры (`IP_1`, `HOST_2`, `PERSON_3`). Словарь
соответствий живёт только локально; ответ модели размаскировывается обратно
для аналитика.

## Быстрый старт

```bash
cp .env.example .env
# сгенерировать токен и его хэш для API_KEYS:
python -c "import hashlib,secrets;t=secrets.token_urlsafe(32);print('token:',t);print('sha256:',hashlib.sha256(t.encode()).hexdigest())"
# впишите admin:<hash>,operator:<hash> в API_KEYS, а сырой operator-токен — в SANITIZER_SERVICE_KEY

# контур SOAR
docker compose -f docker-compose.soar.yml up -d --build
docker compose -f docker-compose.soar.yml exec ollama ollama pull qwen2.5:32b

# контур Pentest — сначала пропишите scope!
$EDITOR engagement/engagement.yml     # allowed_cidrs / allowed_hosts / excluded
docker compose -f docker-compose.pentest.yml up -d --build
docker compose -f docker-compose.pentest.yml exec ollama ollama pull qwen2.5:32b
```

### Пример: SOAR
```bash
curl -s http://127.0.0.1:8010/v1/advise \
  -H "x-api-key: <operator-token>" -H "content-type: application/json" \
  -d '{"incident_id":"INC-42","source":"EDR","title":"Suspicious PowerShell",
       "raw":"host WKS-17 (10.0.4.17) user ivanov ran encoded PS ...",
       "enrich_external":false}'
```

### Пример: Pentest (человек в цикле)
```bash
# 1. модель предлагает шаг (ничего не выполняется)
curl -s http://127.0.0.1:8020/v1/plan -H "x-api-key: <operator-token>" \
  -H "content-type: application/json" \
  -d '{"objective":"external surface recon","last_output":null}'
#   → вернёт step_id, proposed{tool,target}, scope_ok

# 2. человек подтверждает КОНКРЕТНЫЙ шаг → только теперь запуск
curl -s http://127.0.0.1:8020/v1/approve -H "x-api-key: <operator-token>" \
  -H "content-type: application/json" \
  -d '{"step_id":"<из шага 1>","approved":true,"analyze_route":"local"}'
```

## Предохранители — что и зачем

Это не «бумажные» требования, а механизмы, без которых инструмент опасен сам по себе.

**Общее (оба контура):**
- **Санитайзер** (`shared/sanitizer/`) — реверсивная маскировка IP/хостов/ПДн/секретов
  на внешнем маршруте. Прямой ответ на вопрос «как безопасно отправлять во внешний ИИ».
- **Аутентификация** — API-ключи (sha256, сравнение константным временем) + rate limiting.
- **Роли** — viewer / operator / admin, минимум привилегий на эндпоинтах.
- **Аудит** — append-only журнал всех обращений к моделям и запусков.

**Контур 2 (пентест) — дополнительно:**
1. **Scope / RoE** (`scope.py`) — цель обязана попадать в `allowed_cidrs`/`allowed_hosts`
   и не быть в `excluded`. Проверка дважды: при планировании и перед запуском.
   Без этого агент может увести сканер за границы согласованного — это правовой риск.
2. **Allowlist инструментов** (`tools.py`) — только зарегистрированные обёртки над
   стандартными сканерами. **Произвольный shell невозможен** (`shell=False`,
   аргументы списком, валидация регексом). LLM-агент с доступом к shell — плохая идея.
3. **Human-in-the-loop** — ни один запуск без явного `/approve` от человека.
4. **Потолок интенсивности** — `max_intensity` в RoE ограничивает класс инструментов.

> Контур 2 — аналитический слой над штатным инструментарием аудита защищённости
> (nmap/nuclei и т.п.). Эксплойтов в нём нет; активные действия выполняют
> стандартные сканеры строго в границах подписанного scope. Legal-основание
> (договор, RoE, согласие заказчика) — обязательно до запуска.

## Перед продакшеном

- reverse-proxy (nginx/traefik) с TLS 1.2+ перед портами `8010/8020` (сейчас — только localhost);
- секреты — в Vault / Яндекс Lockbox вместо `.env`;
- аудит-журналы — пересылка в SIEM;
- ротация API-ключей.

> Про ПДн: SOAR обрабатывает логи с ФИО/учётками, пентест-находки содержат данные
> о людях и инфраструктуре заказчика. Даже вне КИИ это персональные данные —
> держите разграничение доступа, аудит и обезличивание при передаче вовне.
> Как оформлять — вопрос договора с заказчиком.

## Выбор локальной модели

| Задача | Модель | VRAM (Q4) |
|---|---|---|
| Разбор логов/конфигов, SOAR | Qwen2.5-Coder 32B | ~24 ГБ |
| Универсальный анализ/отчёты | Llama 3.3 70B | ~40–48 ГБ |
| Цепочки рассуждений | DeepSeek-R1 distill | зависит от distill |

Меняется через `LOCAL_MODEL` в `.env` + `ollama pull <model>`.

## Два способа работать вместо curl

### Веб-интерфейс (localhost:8080)
```bash
docker compose -f docker-compose.webui.yml up -d
# откройте http://127.0.0.1:8080
```
Вверху впишите operator-токен → **Connect** (точки у `soar`/`pentest` станут зелёными).
Вкладка **Incident triage** — форма инцидента и разбор. Вкладка **Pentest loop** —
кнопки Propose step → Approve & run, вывод и находки с цветами по severity.
Токен хранится только на время вкладки браузера (sessionStorage).

### Интерактивный скрипт (без Docker, только Python)
```bash
export AISEC_TOKEN=<operator-token>
python3 aisec.py soar        # интерактивный ввод инцидента (или флаги --id/--title/--raw)
python3 aisec.py pentest     # пошаговый цикл: предложение → a/r/q → вывод и разбор
```
Скрипт ведёт весь цикл сам, вывод предыдущего шага автоматически подаётся в следующий.
Флаги `--enrich` (SOAR) и `--analyze-external` (pentest) включают обезличенный внешний ИИ.
