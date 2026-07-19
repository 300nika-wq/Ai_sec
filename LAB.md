# Лабораторный стенд — тренировочный полигон

Поднимает ваш пентест-контур **плюс набор намеренно уязвимых мишеней** в одной
изолированной docker-сети. Scope заранее прописан на все мишени,
`max_intensity: full`. Всё, что вы сканируете, — ваше и легально.

## Набор мишеней

| Мишень | Тип | В браузере | Чему учит |
|---|---|---|---|
| **OWASP Juice Shop** | web (SPA+REST) | http://127.0.0.1:3000 | Широкий OWASP Top-10, современный стек |
| **DVWA** | web | http://127.0.0.1:3001 | Классика: SQLi, XSS, CSRF, upload; уровни сложности |
| **OWASP WebGoat** | web (уроки) | http://127.0.0.1:3002/WebGoat | Пошаговые задания по каждому классу уязвимостей |
| **VAmPI** | api (REST) | http://127.0.0.1:3003 | API Top-10: BOLA, broken auth, mass assignment |
| **Metasploitable2** | network | http://127.0.0.1:3004 | Не-веб сервисы: FTP/SSH/telnet/SMB/SNMP/MySQL |
| **Vulnerable LLM App** | ai/llm | http://127.0.0.1:3005 | Prompt injection, утечка системного промпта, excessive agency |
| **Vulnerable RAG App** | ai/rag | http://127.0.0.1:3006 | Indirect prompt injection через отравление корпуса (LLM08+LLM01) |
| **DVGA (GraphQL)** | api/graphql | http://127.0.0.1:3007 | GraphQL: introspection, инъекции в резолверы |
| **Cloud/Secrets Misconfig** | cloud | http://127.0.0.1:3008 | Утечка секретов (.env/.git/debug) + IMDS SSRF |
| **Poisoned MCP Server** | ai/mcp | http://127.0.0.1:3009 | Agentic supply chain / tool poisoning (LLM03) |

Внутри docker-сети мишени доступны по именам `juiceshop`, `dvwa`, `webgoat`, `vampi` —
`metasploitable` — именно их видит сканер и именно они прописаны в `engagement/engagement.lab.yml`.

## Запуск

```bash
cp .env.example .env          # + вписать токены (см. основной README)
docker compose -f docker-compose.lab.yml up -d --build
docker compose -f docker-compose.lab.yml exec ollama ollama pull qwen2.5:32b
```
Первый старт скачает образы мишеней — это разово. Проверка:
```bash
curl http://127.0.0.1:8020/healthz          # engagement: LAB-TRAINING, max_intensity: full
```

## Веб-панель (рекомендуется)

```bash
docker compose -f docker-compose.webui.yml up -d      # http://127.0.0.1:8080
```
Впишите operator-токен -> Connect. Три вкладки:

- **Incident triage** — SOAR-разбор инцидента.
- **Pentest loop** — цикл предложение -> approve -> скан -> находки.
- **Lab dashboard** — новое: активный scope, все мишени со статусом up/down и
  кнопкой «Открыть», плюс живой журнал действий (авто-обновление раз в 5 сек).
  Отсюда видно, какие мишени подняты, какие в scope, и что уже сканировалось.
  У каждой мишени — раскрываемый блок «Учебные цели» с задачами и подсказкой-
  решением (скрыта под отдельным спойлером, чтобы можно было сначала попробовать сам).

## Прогон цикла

Через панель (Pentest loop) или скриптом:
```bash
export AISEC_TOKEN=<operator-token>
python3 aisec.py pentest --objective "аудит веб-приложения juiceshop"
# или по другой мишени:
python3 aisec.py pentest --objective "аудит REST API vampi"
# сетевая мишень (не веб):
python3 aisec.py pentest --objective "энумерация сервисов metasploitable: smb, snmp, ssh"
# тестирование ИИ-приложения (новый класс):
python3 aisec.py pentest --objective "проверить vulnllm на prompt injection и утечку системного промпта"
# indirect injection через RAG (две фазы: rag_poison -> rag_query):
python3 aisec.py pentest --objective "отравить корпус ragapp и триггернуть indirect injection"
# новые классы:
python3 aisec.py pentest --objective "снять схему GraphQL с dvga через introspection"
python3 aisec.py pentest --objective "найти утечки секретов и IMDS на misconfig"
python3 aisec.py pentest --objective "проверить mcppoison на tool poisoning"
```
Типовая последовательность, которую предлагает модель:
1. `dns_lookup <host>` — резолв в сети;
2. `nmap_service <host> ports=...` — открытые порты и сервисы;
3. `http_headers http://<host>:<port>` — заголовки, стек, редиректы;
4. `nuclei_scan http://<host>:<port>` — шаблоны мисконфигов/CVE (режим full).

## Доступные инструменты

Набор в allowlist (`pentest/app/tools.py`), сгруппирован по интенсивности. В лабе
`max_intensity: full` — доступны все. В боевом `safe-active` инструменты класса
`full` автоматически заблокированы.

| Инструмент | Класс | Что делает |
|---|---|---|
| `dns_lookup`, `whois` | passive | Резолв, регистрационные данные |
| `nmap_service` | safe-active | Открытые порты и сервисы (`ports=...`) |
| `http_headers` | safe-active | HTTP-заголовки, редиректы, стек |
| `whatweb` | safe-active | Fingerprinting: CMS, сервер, технологии |
| `tls_check` | safe-active | Аудит TLS-шифров |
| `enum_services` | safe-active | Версии сервисов + безопасные NSE-скрипты |
| `nmap_smb` | safe-active | SMB: ОС, шары, пользователи, режим безопасности |
| `smb_shares` | safe-active | Анонимный список SMB-ресурсов |
| `snmp_check` | safe-active | Обход SNMP с community `public` |
| `ldap_search` | safe-active | Анонимный LDAP-запрос корня дерева |
| `ssh_audit` | safe-active | Аудит алгоритмов и конфигурации SSH |
| `llm_probe` | safe-active | Тест LLM-приложения на prompt injection (probe: system_leak\|secret_leak\|role_confuse\|tool_misuse) |
| `rag_poison` | safe-active | Фаза 1: посадить отравленный документ в RAG-корпус |
| `rag_query` | safe-active | Фаза 2: безобидный запрос, триггерящий инъекцию |
| `graphql_introspection` | safe-active | Раскрытие схемы GraphQL через introspection |
| `secrets_scan` | safe-active | Проверка путей утечки секретов (.env/.git/debug/IMDS) |
| `mcp_scan` | safe-active | Поиск tool poisoning в метаданных MCP-сервера |
| `nuclei_scan` | full | Шаблоны известных мисконфигов/CVE |
| `nikto` | full | Веб-сканер: уязвимые файлы, мисконфиги |
| `content_discovery` | full | Скрытые пути по словарю (`wordlist=common\|big`) |
| `nmap_vuln` | full | NSE vuln-скрипты: уязвимости сервисов |
| `sqlmap` | full | Тест параметра на SQL-инъекцию (щадящий режим) |

Актуальный список всегда виден по `GET /v1/tools` и учитывается планировщиком
автоматически. Добавить свой инструмент — новая обёртка в `tools.py` (с валидацией
аргументов и классом интенсивности); менять больше ничего не нужно.

## Что смотреть в обучении

- **Предохранители.** Наведите шаг на хост вне списка (`allowed_hosts`) — увидите
  «вне scope», approve недоступен. На панели такая мишень тоже помечается «вне scope».
- **Human-in-the-loop.** Ни один скан не идёт без вашего approve.
- **Аудит.** Вкладка Lab dashboard показывает журнал в реальном времени; он же —
  доказательная база для отчёта:
  ```bash
  docker compose -f docker-compose.lab.yml exec pentest cat /data/audit/pentest.log
  ```
- **Анализ моделью.** Как вывод сканера превращается в findings с severity.

## Добавить свою мишень

1. Добавьте сервис в `docker-compose.lab.yml` (в сети `labnet`, с `aliases: [ имя ]`).
2. Впишите это `имя` в `allowed_hosts` внутри `engagement/engagement.lab.yml`.
3. Добавьте запись в `engagement/targets.lab.yml` (name/host/port/url/kind/description) —
   тогда мишень появится на панели со статусом и кнопкой «Открыть».

Популярные варианты для расширения: bWAPP, Mutillidae II, OWASP crAPI (API),
Metasploitable2 (сетевая поверхность), DVGA (GraphQL).

## Остановить

```bash
docker compose -f docker-compose.lab.yml down
```

> Стенд полностью локальный (всё на `127.0.0.1`). Мишени уязвимы намеренно —
> держите их только в лабораторной сети и никогда не публикуйте наружу.

## Отчёт по сессии

Любой прогон превращается в отчёт: находки дедуплицируются, группируются по severity
и выгружаются в Markdown.
- CLI: в конце цикла предложит `Сохранить отчёт по сессии в .md?`.
- Веб: вкладка Pentest loop / Lab dashboard → кнопка «Отчёт по сессии» (просмотр + скачивание).
- API: `GET /v1/report/{session_id}` (JSON) или `/v1/report/{session_id}/markdown?save=true`.

Отчёт помечен как требующий ручной верификации — модель выделяет находки, но
последнее слово за человеком.

**Покрытие таксономий.** Каждая находка автоматически размечается по OWASP LLM
Top 10 (2025), OWASP Web Top 10 (2021) и MITRE ATLAS (детерминированно, по
инструменту и ключевым словам). В отчёте есть сводка покрытия — прогон сразу
ложится в стандартный словарь для заказчика и SOC.

## Тестирование ИИ-приложений

Мишень `vulnllm` и инструмент `llm_probe` — про новый класс задач: пентест самих
LLM-приложений. Практикуются prompt injection, утечка системного промпта и
excessive agency (когда приложение слепо доверяет выводу модели и выполняет
«админ-действие»). `llm_probe` шлёт стандартные тест-payload'ы (по мотивам
garak/promptfoo); для глубокого тестирования смотрите garak, PyRIT, promptfoo.
