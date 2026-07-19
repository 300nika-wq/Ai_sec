# AI-SEC Stack — полное руководство по развёртыванию и использованию

Самодостаточная инструкция: от чистой машины до работающего полигона.
Читать по порядку. Команды можно копировать как есть.

---

## 0. Что вы разворачиваете

Два ИИ-контура для ИБ с общим санитайзером плюс тренировочный полигон:

- **SOAR-советник** — по инциденту даёт рекомендации по реагированию.
- **Пентест-оркестратор** — цикл «модель предлагает шаг -> человек подтверждает ->
  запускается инструмент -> разбор». 20 инструментов, 7 уязвимых мишеней.
- **Санитайзер** — маскирует IP/ПДн/секреты, если запрос уходит во внешний ИИ.
- **Веб-интерфейс** — 4 вкладки: Incident triage, Pentest loop, Lab dashboard, Arsenal.
- **Полигон** — 7 легальных уязвимых мишеней (web, API, сеть, LLM, RAG).

Всё локально, весь трафик слушается только на 127.0.0.1.

---

## 1. Требования

**Софт:**
- Docker + Docker Compose (Docker Desktop на Windows/macOS или Docker Engine на Linux).
- Python 3.10+ на хосте — только для CLI (aisec.py). Для веб-интерфейса не нужен.

**Железо:**
- Модель по умолчанию qwen2.5:32b — ~24 ГБ VRAM или Mac с 32+ ГБ памяти.
- Слабее железо -> в шаге 3 поставьте qwen2.5:7b (8-12 ГБ).
- Диск: ~30-40 ГБ на образы (модель + мишени).

---

## 2. Установка

```bash
unzip ai-security-stack.zip
cd ai-security-stack
cp .env.example .env
```

---

## 3. Настройка .env (токены доступа)

Сервисы не пускают без ключа. Сгенерируйте токены — выполните **дважды**
(для роли admin и роли operator):
```bash
python3 -c "import hashlib,secrets;t=secrets.token_urlsafe(32);print('token:',t);print('sha256:',hashlib.sha256(t.encode()).hexdigest())"
```
Каждый запуск даёт пару token: (сырой) и sha256: (хэш).

В .env заполните:
```ini
# хэши обоих токенов:
API_KEYS=admin:<sha256_от_admin>,operator:<sha256_от_operator>
# СЫРОЙ operator-токен (им сервисы ходят в санитайзер):
SANITIZER_SERVICE_KEY=<сырой_operator_token>
# локальная модель (qwen2.5:7b если мало памяти):
LOCAL_MODEL=qwen2.5:32b
# внешний ИИ по умолчанию ВЫКЛЮЧЕН — всё работает локально:
ALLOW_EXTERNAL=false
```

**Сохраните сырой operator-токен отдельно** — он нужен для входа в интерфейс и CLI.
Из хэша его не восстановить.

---

## 4. Запуск полигона

```bash
# поднять весь стенд (контур + 7 мишеней)
docker compose -f docker-compose.lab.yml up -d --build

# скачать модель (разово, ~20 ГБ)
docker compose -f docker-compose.lab.yml exec ollama ollama pull qwen2.5:32b

# поднять веб-интерфейс
docker compose -f docker-compose.webui.yml up -d
```

Проверка:
```bash
curl http://127.0.0.1:8020/healthz
# {"status":"ok","engagement":"LAB-TRAINING","max_intensity":"full"}
```

---

## 5. Первый вход через веб-интерфейс

1. Откройте http://127.0.0.1:8080
2. Впишите operator-токен (сырой) в поле «Operator token».
3. Нажмите Connect — точки soar и pentest станут зелёными.

Поля URL менять не нужно — дефолты для локального запуска.

### Вкладки

- **Incident triage (SOAR):** заполнить инцидент -> Get recommendation -> оценка,
  severity, MITRE, шаги реагирования.
- **Pentest loop:** objective -> Propose step -> Approve & run. Инструмент
  запускается только после подтверждения. Кнопка «Отчёт по сессии» собирает отчёт.
- **Lab dashboard:** scope, все 7 мишеней (up/down, «Открыть»), живой журнал.
  У каждой мишени — «Учебные цели» с задачами и подсказкой-решением.
- **Arsenal:** все 20 инструментов с фильтром по интенсивности; запуск выбранного
  инструмента напрямую (порты/словарь/probe под конкретный инструмент).

---

## 6. Использование через CLI (альтернатива)

```bash
export AISEC_TOKEN=<сырой_operator_token>

# SOAR:
python3 aisec.py soar --id INC-1 --source EDR --title "Suspicious PowerShell" \
  --raw "host WKS-17 (10.0.4.17) user ivanov ran encoded PS"

# Пентест (пошагово: a=approve, r=reject, q=quit):
python3 aisec.py pentest --objective "аудит веб-приложения juiceshop"
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

Сканер обращается по host (juiceshop, http://vulnllm:8000), вы открываете по 127.0.0.1:порт.

---

## 8. Инструменты (allowlist)

- **passive:** dns_lookup, whois
- **safe-active:** nmap_service, http_headers, whatweb, tls_check, enum_services,
  nmap_smb, smb_shares, snmp_check, ldap_search, ssh_audit, llm_probe, rag_poison, rag_query
- **full:** nuclei_scan, nikto, content_discovery, nmap_vuln, sqlmap

В лабе max_intensity: full — доступны все.

---

## 9. Учебные сценарии

**Web (Juice Shop):**
`objective: аудит веб-приложения juiceshop`
шаги: http_headers -> whatweb -> content_discovery -> nuclei_scan

**Сеть (Metasploitable2):**
`objective: энумерация сервисов metasploitable: smb, snmp, ssh`
шаги: enum_services -> nmap_smb -> smb_shares -> snmp_check

**LLM (prompt injection):**
`objective: проверить vulnllm на prompt injection и утечку системного промпта`
инструмент: llm_probe (probe: system_leak / secret_leak / tool_misuse)

**RAG (indirect injection, две фазы):**
`objective: отравить корпус ragapp и триггернуть indirect injection`
шаг 1: rag_poison -> шаг 2: rag_query

ИИ-мишени удобно пробовать руками в веб-песочницах (3005 и 3006).

---

## 10. Отчёты

Прогон -> отчёт с дедупликацией, группировкой по severity и маппингом на
OWASP LLM Top 10 / OWASP Web Top 10 / MITRE ATLAS.
- Веб: кнопка «Отчёт по сессии».
- CLI: предложит сохранить в конце.
- API: GET /v1/report/{session_id} или /v1/report/{session_id}/markdown?save=true

---

## 11. Управление стендом

```bash
docker compose -f docker-compose.lab.yml ps                    # статус
docker compose -f docker-compose.lab.yml logs -f ollama        # логи модели
docker compose -f docker-compose.lab.yml logs -f pentest       # логи контура
docker compose -f docker-compose.lab.yml exec pentest cat /data/audit/pentest.log  # аудит
docker compose -f docker-compose.lab.yml up -d --build pentest # пересобрать сервис
docker compose -f docker-compose.lab.yml down                  # остановить
docker compose -f docker-compose.webui.yml down
```

---

## 12. Если что-то не работает

| Симптом | Решение |
|---|---|
| Точки красные | Сервис не поднялся (ps) или неверный токен (сырой из SANITIZER_SERVICE_KEY) |
| 401 | Токен не тот / не вставлен |
| 403 «вне scope» | Цель не в allowed_hosts — это предохранитель |
| 429 | Rate limit, подождите минуту |
| Модель долго / контейнер падает | Мало памяти -> LOCAL_MODEL=qwen2.5:7b + ollama pull qwen2.5:7b |
| Мишень «down» | Контейнер ещё стартует (Metasploitable/WebGoat дольше) |
| «Внешний маршрут запрещён» | ALLOW_EXTERNAL=false — норма |
| llm_probe/rag_query «пусто» | Мишень грузит модель при первом запросе — повторите |

---

## 13. Отдельные контуры (без полигона)

```bash
docker compose -f docker-compose.soar.yml up -d --build       # только SOAR
docker compose -f docker-compose.pentest.yml up -d --build    # только пентест (боевой scope!)
```
Для боевого пентеста заполните engagement/engagement.yml строго по подписанному scope.
Перед продом закройте TODO из README.md (reverse-proxy с TLS, секреты в Vault, аудит в SIEM).

---

## 14. Важные оговорки

- Мишени намеренно уязвимы — только в локальной сети, не публиковать наружу.
- Всё на 127.0.0.1 — снаружи хоста доступа нет.
- Инструменты запускаются строго по мишеням из scope, через подтверждение и с аудитом.
- Безопасность держат детерминированные слои (scope, allowlist, human approval,
  аудит), а не языковая модель.

Полигон готов. Начинайте с вкладки Lab dashboard и учебных целей у мишеней.
