# AI-SEC — тренировочный полигон по безопасности ИИ

Самодостаточный стек для обучения пентесту и безопасности LLM-приложений:
оркестратор пентеста (human-in-the-loop) + веб-панель + набор намеренно уязвимых
мишеней (web / API / сеть / **LLM / RAG / MCP**). Локальная модель (Ollama)
вызывается **напрямую** — никаких внешних сервисов, всё работает офлайн.

| Компонент | Что делает | Порт (localhost) |
|---|---|---|
| **pentest** (`docker-compose.lab.yml`) | Оркестратор: модель предлагает шаг → человек подтверждает → запуск стандартного сканера → разбор вывода локальной моделью | 8020 |
| **webui** (`docker-compose.webui.yml`) | Веб-панель: Pentest loop, Lab dashboard, Arsenal | 8080 |
| **мишени** (в `docker-compose.lab.yml`) | 10 намеренно уязвимых приложений в изолированной сети | 3000–3009 |
| **garak** (`docker-compose.garak.yml`, опц.) | Отдельный стек: LLM-сканер garak + своя панель | 8030 |

## Архитектура

```
[аналитик] → веб-панель / CLI → pentest API (8020) → Ollama (локальная модель)
                                      │
                                      └── стандартные сканеры (nmap/nikto/curl-пробы…) в границах scope
```

Модель нужна оркестратору (предлагает шаги, разбирает вывод) и двум ИИ-мишеням
(`vulnllm`, `ragapp`). Все читают единый `OLLAMA_URL`. Данные никуда не уходят —
это изолированный полигон.

## Быстрый старт

```bash
cp .env.example .env
# сгенерировать токены admin и operator и их sha256:
python3 -c "import hashlib,secrets;t=secrets.token_urlsafe(32);print('token:',t,'sha256:',hashlib.sha256(t.encode()).hexdigest())"
# впишите admin:<hash>,operator:<hash> в API_KEYS

docker compose -f docker-compose.lab.yml up -d --build
docker compose -f docker-compose.lab.yml exec ollama ollama pull qwen2.5:7b   # или 3b
docker compose -f docker-compose.webui.yml up -d

curl http://127.0.0.1:8020/healthz      # engagement: LAB-TRAINING
# откройте http://127.0.0.1:8080 , впишите operator/admin-токен -> Connect
```

## Пример: Pentest loop (человек в цикле)

```bash
# 1. модель предлагает шаг (ничего не выполняется)
curl -s http://127.0.0.1:8020/v1/plan -H "x-api-key: <operator-token>" \
  -H "content-type: application/json" \
  -d '{"objective":"lab recon","last_output":null}'
#   → вернёт step_id, proposed{tool,target}, scope_ok

# 2. человек подтверждает КОНКРЕТНЫЙ шаг → только теперь запуск
curl -s http://127.0.0.1:8020/v1/approve -H "x-api-key: <operator-token>" \
  -H "content-type: application/json" \
  -d '{"step_id":"<из шага 1>","approved":true}'
```

## Предохранители — что и зачем

Это механизмы, без которых оркестратор сканеров был бы опасен сам по себе:

1. **Scope / RoE** (`scope.py`) — цель обязана попадать в `allowed_hosts`/
   `allowed_cidrs` и не быть в `excluded`. Проверка **дважды**: при планировании и
   перед запуском (defense in depth).
2. **Allowlist инструментов** (`tools.py`) — только зарегистрированные обёртки над
   стандартными сканерами. **Произвольный shell невозможен** (`shell=False`,
   аргументы списком, валидация регексом).
3. **Human-in-the-loop** — ни один запуск без явного `/approve` от человека.
4. **Потолок интенсивности** — `max_intensity` в RoE ограничивает класс инструментов.
5. **Аутентификация** — API-ключи (sha256, сравнение константным временем) + rate limit.
6. **Роли** — operator / admin (admin может менять scope, адрес мишеней, настройки модели).
7. **Аудит** — append-only журнал всех предложений, подтверждений и запусков.

> Оркестратор — аналитический слой над штатным инструментарием аудита защищённости
> (nmap/nikto/curl-пробы). Эксплойтов в нём нет; активные действия выполняют
> стандартные сканеры строго в границах scope. Все мишени — намеренно уязвимые
> приложения, поднятые вами в изолированной сети, поэтому сканировать их законно.

## Мишени (10)

web: **Juice Shop**, **DVWA**, **WebGoat** · api: **VAmPI**, **DVGA (GraphQL)** ·
network: **Metasploitable2** · cloud: **misconfig** (утечки/IMDS) ·
**ai/llm: vulnllm** · **ai/rag: ragapp** · **ai/mcp: mcppoison** (tool poisoning).

Инструменты тестирования ИИ: `llm_probe` (injection/jailbreak), `llm_pii_leak`,
`llm_output_handling`, `rag_poison`/`rag_query`/`rag_exfil`, `mcp_scan`/`mcp_tool_invoke`.

## Выбор локальной модели

| Железо | Модель | Заметка |
|---|---|---|
| Слабое | `qwen2.5:3b` | ИИ-мишени тянет; оркестратору JSON даётся хуже |
| Среднее | `qwen2.5:7b` | рекомендуемый минимум для оркестратора |
| Мощное | `qwen2.5:32b` / `llama3.1:70b` | лучший разбор |

Меняется через `LOCAL_MODEL` в `.env` (+ `ollama pull <model>`) **или на лету** в
панели: Lab dashboard → «Настройки ИИ» (там же адрес Ollama — можно указать другой сервер).

## Работать без curl

**Веб-панель** (`http://127.0.0.1:8080`): впишите токен → **Connect**. Вкладки:
Pentest loop (Propose → Approve & run), Lab dashboard (scope, мишени, редакторы
scope/модели/адреса мишеней, журнал), Arsenal (все инструменты allowlist).

**CLI** (только Python, без Docker):
```bash
export AISEC_TOKEN=<operator-token>
python3 aisec.py pentest     # пошаговый цикл: предложение → a/r/q → вывод и разбор
```

## Опционально: garak (глубокий LLM-скан)

Отдельный тяжёлый стек (torch/transformers) со своей панелью на `:8030`. Подробно —
в `ADMIN_GUIDE.md`, раздел 11b.
```bash
docker compose -f docker-compose.garak.yml up -d --build   # после того как lab поднят
```

## Документация

- `ADMIN_GUIDE.md` — развёртывание, эксплуатация, scope, мишени, инструменты, garak.
- `LAB.md` — прохождение заданий на мишенях.
- `GETTING_STARTED.md` — пошаговый первый запуск.

## Перед выносом за пределы изолированной сети

Полигон рассчитан на **локальную/изолированную** среду (мишени намеренно уязвимы).
Не публикуйте порты наружу. Для доступа с других машин — reverse-proxy с TLS и
аутентификацией; секреты — вне `.env`; аудит — в SIEM.
