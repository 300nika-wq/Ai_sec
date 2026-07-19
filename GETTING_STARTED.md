# AI-SEC — руководство по развёртыванию и использованию

Самодостаточная инструкция: от чистой машины до работающего полигона.
Читать по порядку. Команды можно копировать как есть.

---

## 0. Что вы разворачиваете

Тренировочный полигон по безопасности (в т.ч. ИИ), всё локально:

- **Пентест-оркестратор** — цикл «модель предлагает шаг → человек подтверждает →
  запускается инструмент → разбор локальной моделью». 27 инструментов, 10 мишеней.
- **Веб-панель** — 3 вкладки: Pentest loop, Lab dashboard, Arsenal.
- **Полигон** — 10 намеренно уязвимых мишеней (web, API, сеть, LLM, RAG, MCP).
- **(опц.) garak** — отдельный стек: глубокий LLM-сканер со своей панелью.

Локальная модель (Ollama) вызывается напрямую. Всё слушается только на 127.0.0.1.

---

## 1. Требования

**Софт:** Docker + Docker Compose. Python 3.10+ на хосте — только для CLI (`aisec.py`).

**Железо:**
- `qwen2.5:7b` (рекомендуется) — ~8–12 ГБ памяти.
- Слабое железо → `qwen2.5:3b` (~2–3 ГБ). Мощное → `qwen2.5:32b`.
- Диск: ~20–40 ГБ на образы (модель + мишени).

---

## 2. Установка

```bash
cp .env.example .env
```

---

## 3. Настройка .env (токены доступа)

Сервис не пускает без ключа. Сгенерируйте токены — выполните **дважды**
(для роли admin и роли operator):
```bash
python3 -c "import hashlib,secrets;t=secrets.token_urlsafe(32);print('token:',t);print('sha256:',hashlib.sha256(t.encode()).hexdigest())"
```
Каждый запуск даёт `token:` (сырой) и `sha256:` (хэш).

В `.env` заполните:
```ini
# хэши обоих токенов:
API_KEYS=admin:<sha256_от_admin>,operator:<sha256_от_operator>
# локальная модель (qwen2.5:3b если совсем мало памяти):
LOCAL_MODEL=qwen2.5:7b
```

**Сохраните сырые токены отдельно** — они нужны для входа в панель и CLI
(admin — для правки scope/адресов/модели, operator — для обычной работы). Из хэша
их не восстановить.

---

## 4. Запуск полигона

```bash
# поднять весь стенд (оркестратор + 10 мишеней)
docker compose -f docker-compose.lab.yml up -d --build

# скачать модель (разово)
docker compose -f docker-compose.lab.yml exec ollama ollama pull qwen2.5:7b

# поднять веб-панель
docker compose -f docker-compose.webui.yml up -d
```

Проверка:
```bash
curl http://127.0.0.1:8020/healthz
# {"status":"ok","engagement":"LAB-TRAINING","max_intensity":"full", ...}
```

---

## 5. Первый вход через веб-панель

1. Откройте http://127.0.0.1:8080
2. Впишите operator- или admin-токен (сырой) в поле «Operator token».
3. Нажмите **Connect** — точка `pentest` станет зелёной.

Поле URL менять не нужно — дефолт для локального запуска.

### Вкладки

- **Pentest loop:** objective → Propose step → Approve & run. Инструмент
  запускается только после подтверждения. Кнопки отчёта собирают отчёт по сессии.
- **Lab dashboard:** scope, все 10 мишеней (up/down, «Открыть»), живой журнал.
  Здесь же редакторы (нужен admin-токен): **Изменить scope**, **Настройки ИИ**
  (адрес Ollama и модель), **Изменить адрес мишени** (распределённая установка).
  У каждой мишени — «Учебные цели» с задачами и подсказкой.
- **Arsenal:** все 27 инструментов с фильтром по интенсивности; запуск выбранного
  инструмента напрямую (порты/словарь/probe под конкретный инструмент).

---

## 6. Использование через CLI (альтернатива)

```bash
export AISEC_TOKEN=<сырой_operator_token>
python3 aisec.py pentest --objective "аудит веб-приложения juiceshop"
# пошагово: a=approve, r=reject, q=quit
```
В конце цикла скрипт предложит сохранить отчёт в .md.

---

## 7. Мишени полигона

| Мишень | host (в сети) | Открыть в браузере | Класс |
|---|---|---|---|
| OWASP Juice Shop | juiceshop | http://127.0.0.1:3000 | web |
| DVWA | dvwa | http://127.0.0.1:3001 | web |
| OWASP WebGoat | webgoat | http://127.0.0.1:3002/WebGoat | web |
| VAmPI (API) | vampi | http://127.0.0.1:3003 | api |
| Metasploitable2 | metasploitable | http://127.0.0.1:3004 | network |
| Vulnerable LLM App | vulnllm | http://127.0.0.1:3005 | ai/llm |
| Vulnerable RAG App | ragapp | http://127.0.0.1:3006 | ai/rag |
| DVGA (GraphQL) | dvga | http://127.0.0.1:3007 | api/graphql |
| Cloud/Secrets Misconfig | misconfig | http://127.0.0.1:3008 | cloud |
| Poisoned MCP Server | mcppoison | http://127.0.0.1:3009 | ai/mcp |

Сканер обращается по host (`juiceshop`, `http://vulnllm:8000`), вы открываете по `127.0.0.1:порт`.

---

## 8. Инструменты (allowlist)

- **passive:** dns_lookup, whois
- **safe-active:** nmap_service, http_headers, whatweb, tls_check, enum_services,
  nmap_smb, smb_shares, snmp_check, ldap_search, ssh_audit, llm_probe, llm_pii_leak,
  llm_output_handling, rag_poison, rag_query, rag_exfil, graphql_introspection,
  secrets_scan, mcp_scan, mcp_tool_invoke
- **full:** nuclei_scan, nikto, content_discovery, nmap_vuln, sqlmap

В лабе `max_intensity: full` — доступны все.

---

## 9. Учебные сценарии

**Web (Juice Shop):** `objective: аудит веб-приложения juiceshop`
→ http_headers → whatweb → content_discovery → nuclei_scan

**Сеть (Metasploitable2):** `objective: энумерация сервисов metasploitable`
→ enum_services → nmap_smb → smb_shares → snmp_check

**LLM (prompt injection):** `objective: проверить vulnllm на prompt injection`
→ llm_probe (probe: system_leak / secret_leak / dan_jailbreak / tool_misuse), llm_pii_leak

**RAG (indirect injection, две фазы):** rag_poison (или rag_exfil) → rag_query

**MCP (tool poisoning):** mcp_scan → mcp_tool_invoke

ИИ-мишени удобно пробовать руками в веб-песочницах (3005/3006/3009).

---

## 10. Отчёты

Прогон → отчёт с дедупликацией, группировкой по severity и маппингом на
OWASP LLM Top 10 / OWASP Web Top 10 / MITRE ATLAS.
- Веб: кнопки отчёта в Pentest loop.
- CLI: предложит сохранить в конце.
- API: `GET /v1/report/{session_id}` или `/v1/report/{session_id}/markdown?save=true`

---

## 11. Управление стендом

```bash
docker compose -f docker-compose.lab.yml ps                     # статус
docker compose -f docker-compose.lab.yml logs -f pentest        # логи оркестратора
docker compose -f docker-compose.lab.yml exec pentest cat /data/audit/pentest.log  # аудит
docker compose -f docker-compose.lab.yml up -d --build pentest  # пересобрать сервис
docker compose -f docker-compose.lab.yml down                   # остановить
docker compose -f docker-compose.webui.yml down
```

---

## 12. Если что-то не работает

| Симптом | Решение |
|---|---|
| Точка pentest красная | Сервис не поднялся (`ps`) или неверный токен |
| 401 | Токен не тот / не вставлен |
| 403 «вне scope» | Цель не в allowed_hosts — это предохранитель (admin может добавить) |
| 429 | Rate limit, подождите минуту |
| Модель долго / OOM | Мало памяти → `LOCAL_MODEL=qwen2.5:3b` + `ollama pull qwen2.5:3b` |
| Мишень «down» | Контейнер ещё стартует (Metasploitable/WebGoat дольше) |
| `image ... not found` / `429` при pull | Временный сбой Docker Hub или лимит анонимных пулов. Повторить `docker compose -f docker-compose.lab.yml pull <сервис>`; при повторе — `docker login`, затем `up -d`. Образы реальны, тег менять не нужно |
| llm_probe/rag_query «пусто» | Мишень грузит модель при первом запросе — повторите |
| Панель без нового раздела | Пересоздайте webui (`up -d --force-recreate`) + Ctrl+Shift+R |

---

## 13. Опционально: garak

Отдельный тяжёлый стек (LLM-сканер) со своей панелью на `:8030`. Ставится поверх
поднятого lab-стека:
```bash
docker compose -f docker-compose.garak.yml up -d --build
```
Подробно — в `ADMIN_GUIDE.md`, раздел 11b.

---

## 14. Важные оговорки

- Мишени намеренно уязвимы — только в локальной сети, не публиковать наружу.
- Всё на 127.0.0.1 — снаружи хоста доступа нет.
- Инструменты запускаются строго по мишеням из scope, через подтверждение и с аудитом.
- Безопасность держат детерминированные слои (scope, allowlist, human approval,
  аудит), а не языковая модель.

Полигон готов. Начинайте с вкладки Lab dashboard и учебных целей у мишеней.
