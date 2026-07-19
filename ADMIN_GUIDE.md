# Руководство администратора полигона AI-SEC

Документ для того, кто разворачивает, эксплуатирует, сопровождает и расширяет
тренировочный полигон. Не про прохождение заданий (это в `LAB.md`), а про
управление стендом.

---

## 1. Что администрирует администратор

Полигон — это docker-стек из трёх функциональных слоёв:

1. **Оркестрация (контур пентеста):** сервис `pentest` + `sanitizer` + `ollama`.
2. **Мишени:** 10 намеренно уязвимых приложений в изолированной сети `labnet`.
3. **Интерфейсы доступа:** веб-панель (`webui`, отдельный compose) и CLI (`aisec.py`).

Все порты слушаются только на `127.0.0.1`. Наружу хоста по умолчанию ничего не торчит.

---

## 2. Карта сервисов и портов

| Сервис | Роль | Порт (хост) | Источник |
|---|---|---|---|
| ollama | Локальная LLM (движок инференса) | — (внутр. 11434) | образ ollama/ollama |
| sanitizer | Маскировка/роутер к моделям | — (внутр. 8000) | build ./shared/sanitizer |
| pentest | Оркестратор + API | 8020 | build ./pentest |
| juiceshop | Мишень web | 3000 | bkimminich/juice-shop |
| dvwa | Мишень web | 3001 | vulnerables/web-dvwa |
| webgoat | Мишень web (уроки) | 3002 | webgoat/webgoat |
| vampi | Мишень API | 3003 | erev0s/vampi |
| metasploitable | Мишень network | 3004 | tleemcjr/metasploitable2 |
| vulnllm | Мишень ai/llm | 3005 | build ./targets/vuln-llm-app |
| ragapp | Мишень ai/rag | 3006 | build ./targets/rag-app |
| dvga | Мишень api/graphql | 3007 | dolevf/dvga |
| misconfig | Мишень cloud | 3008 | build ./targets/misconfig-app |
| mcppoison | Мишень ai/mcp | 3009 | build ./targets/mcp-poison |
| webui | Веб-панель (nginx) | 8080 | docker-compose.webui.yml |

Внутри `labnet` мишени доступны сканеру по именам (`juiceshop`, `dvga`, `misconfig` …);
на хосте — по `127.0.0.1:<порт>`.

---

## 3. Файлы и каталоги, которые ведёт админ

```
docker-compose.lab.yml         # стек полигона (контур + мишени)
docker-compose.webui.yml       # веб-панель
.env                           # секреты и конфигурация (НЕ в git)
engagement/engagement.lab.yml  # scope полигона (allowlist мишеней, max_intensity)
engagement/targets.lab.yml     # список мишеней для панели + учебные цели/подсказки
pentest/app/tools.py           # allowlist инструментов (обёртки)
pentest/app/scope.py           # логика проверки scope
pentest/app/taxonomy.py        # маппинг находок на OWASP/ATLAS
targets/<name>/                # исходники самодельных мишеней
webui/index.html               # интерфейс
webui/mgts/                     # дизайн-система (токены + шрифты)
```

Тома Docker: `ollama_models` (скачанная модель), `audit` (журналы действий).

---

## 4. Первичное развёртывание

```bash
unzip ai-security-stack.zip && cd ai-security-stack
cp .env.example .env
```

Сгенерируйте два токена (admin и operator) и заполните `.env`:
```bash
python3 -c "import hashlib,secrets;t=secrets.token_urlsafe(32);print('token:',t);print('sha256:',hashlib.sha256(t.encode()).hexdigest())"
```
```ini
API_KEYS=admin:<sha256_admin>,operator:<sha256_operator>
SANITIZER_SERVICE_KEY=<сырой operator-token>
LOCAL_MODEL=qwen2.5:32b        # или qwen2.5:7b при нехватке памяти
ALLOW_EXTERNAL=false
```

Поднимите стек и скачайте модель:
```bash
docker compose -f docker-compose.lab.yml up -d --build
docker compose -f docker-compose.lab.yml exec ollama ollama pull qwen2.5:32b
docker compose -f docker-compose.webui.yml up -d
```

Проверка:
```bash
curl http://127.0.0.1:8020/healthz     # engagement: LAB-TRAINING, max_intensity: full
```

---

## 5. Роли и доступ

Аутентификация — по API-ключу (`x-api-key`). Формат в `API_KEYS`: `role:sha256(token)`.

- **admin** — полный доступ operator + ручное изменение scope в рантайме (`PUT /v1/scope`).
- **operator** — запуск инструментов, планирование, отчёты, чтение scope/аудита.
- **viewer** — предусмотрен в коде, но эндпоинтам сейчас нужен operator/admin.

Сервисы ходят друг к другу под `SANITIZER_SERVICE_KEY` (сырой operator-токен).

**Ротация ключей:** сгенерируйте новые токены, обновите `API_KEYS` и
`SANITIZER_SERVICE_KEY` в `.env`, пересоздайте сервисы:
`docker compose -f docker-compose.lab.yml up -d`. Старые токены сразу инвалидируются.

---

## 6. Ежедневная эксплуатация

```bash
# статус и здоровье
docker compose -f docker-compose.lab.yml ps
curl http://127.0.0.1:8020/healthz

# логи сервиса
docker compose -f docker-compose.lab.yml logs -f pentest
docker compose -f docker-compose.lab.yml logs --tail=50 ollama

# журнал действий (кто/что/когда сканировал) — доказательная база
docker compose -f docker-compose.lab.yml exec pentest cat /data/audit/pentest.log

# перезапуск одного сервиса
docker compose -f docker-compose.lab.yml restart pentest

# остановить / поднять всё
docker compose -f docker-compose.lab.yml down
docker compose -f docker-compose.lab.yml up -d
```

Веб-панель — статика под nginx; после правок `webui/` достаточно
`docker compose -f docker-compose.webui.yml restart` и Ctrl+Shift+R в браузере.

---

## 7. Управление scope (важнейший рычаг)

Scope в `engagement/engagement.lab.yml` определяет, что оркестратору **разрешено**
трогать. Это монтируется в контейнер read-only.

```yaml
engagement_id: "LAB-TRAINING"
max_intensity: "full"      # passive | safe-active | full — потолок агрессивности
allowed_hosts:             # только эти цели агент может сканировать
  - "juiceshop"
  ...
excluded: []               # что не трогать никогда
```

- Убрать мишень из работы — удалить её из `allowed_hosts`.
- Ограничить агрессивность на группе — понизить `max_intensity` (тогда инструменты
  класса `full` заблокируются автоматически).
- После правки: `docker compose -f docker-compose.lab.yml restart pentest`.

Проверка активного scope: `GET http://127.0.0.1:8020/v1/scope` (с operator-токеном)
или вкладка Lab dashboard.

**Ручное изменение scope без перезапуска (admin).** Для быстрой правки прямо во
время занятия есть `PUT /v1/scope` — меняет `allowed_hosts` / `excluded` /
`max_intensity` в памяти процесса. Доступно **только под admin-токеном** (это
предохранитель — операторам менять границы нельзя). Каждое изменение пишется в
аудит (`scope_updated`). Файл `engagement.lab.yml` остаётся источником истины:
перезапуск `pentest` возвращает scope к файлу — то есть рантайм-правка временная.

- В панели: вкладка **Lab dashboard → «Изменить scope вручную»** (нужен admin-токен
  в поле Operator token).
- Из консоли (передавайте только изменяемые поля):
  ```bash
  curl -X PUT http://127.0.0.1:8020/v1/scope \
    -H "x-api-key: <admin-token>" -H "content-type: application/json" \
    -d '{"max_intensity":"safe-active","allowed_hosts":["juiceshop","dvwa"]}'
  ```

Постоянное изменение — по-прежнему через правку `engagement.lab.yml` + restart.

---

## 8. Добавить новую мишень

1. Добавьте сервис в `docker-compose.lab.yml` (в сети `labnet`, с уникальным
   `aliases: [ имя ]` и свободным портом хоста).
2. Впишите `имя` в `allowed_hosts` в `engagement/engagement.lab.yml`.
3. Добавьте запись в `engagement/targets.lab.yml` (`name/host/port/url/kind/description`
   плюс `objectives` и `hint` для учебной панели).
4. Поднимите: `docker compose -f docker-compose.lab.yml up -d --build <имя>` и
   перезапустите pentest, если правили scope.

Мишень появится на панели со статусом up/down, кнопкой «Открыть» и подсказками.

---

## 9. Добавить/изменить инструмент

Инструменты — обёртки в `pentest/app/tools.py`. Каждая: формирует команду списком
аргументов (без shell), валидирует цель, имеет класс интенсивности и таймаут.

Шаги:
1. Напишите функцию-обёртку `_mytool(target, **_) -> list` с `_require_bin(...)` и
   `_validate_target(...)` / `_validate_url(...)`.
2. Зарегистрируйте в `REGISTRY` с именем, классом (`passive`/`safe-active`/`full`),
   описанием и таймаутом.
3. При необходимости — доустановите бинарь в `pentest/Dockerfile`.
4. (Опц.) добавьте маппинг находок в `pentest/app/taxonomy.py`.
5. Пересоберите: `docker compose -f docker-compose.lab.yml up -d --build pentest`.

Планировщик и вкладка Arsenal подхватят инструмент автоматически (список из `/v1/tools`).

**Граница:** не добавляйте в агент автоматизированный брутфорс/подбор паролей —
это инструмент двойного назначения; такие вещи показывают ручным запуском вне
оркестратора.

---

## 10. Сброс состояния мишеней

Мишени с изменяемым состоянием (`ragapp` после отравления корпуса, DVWA после
изменений) сбрасываются пересозданием контейнера:
```bash
docker compose -f docker-compose.lab.yml up -d --force-recreate ragapp
```
Для группового обучения удобно сбрасывать перед каждой сессией.

---

## 11. Модель: полегче или на отдельном сервере

Модель нужна **дважды**: оркестратору (предлагает шаги, разбирает вывод) и трём
ИИ-мишеням (`vulnllm`, `ragapp` — сами являются LLM-приложениями). Все читают
**единую точку** `OLLAMA_URL` и `LOCAL_MODEL` из `.env`. Остальные 7 мишеней
модель не используют.

**Не хватает мощности — модель полегче (проще всего):**
```ini
# .env
LOCAL_MODEL=qwen2.5:7b          # ~8-12 ГБ; или llama3.1:8b
# LOCAL_MODEL=qwen2.5:3b        # ~2-3 ГБ для совсем слабого железа (см. ниже)
```
```bash
docker compose -f docker-compose.lab.yml exec ollama ollama pull qwen2.5:7b
docker compose -f docker-compose.lab.yml restart pentest sanitizer vulnllm ragapp
```
И оркестратор, и ИИ-мишени возьмут новую модель — переключение одной строкой.

`qwen2.5:3b` — самый лёгкий рабочий вариант: ИИ-мишени (`vulnllm`, `ragapp`)
на нём тренируются нормально (им надо просто отвечать и «вестись» на инъекции),
но оркестратору строгий JSON для `/plan` и разбора вывода даётся хуже — если в
панели/CLI вместо структуры мелькает «сырой» ответ (`_parse_error`), поднимите
до `qwen2.5:7b`. Ниже 3b (напр. `qwen2.5:1.5b`) для оркестратора не рекомендуется.

**Ollama уже развёрнут на другом сервере (переключение флагом):**
Локальный движок вынесен в docker-профиль `local-model`, поэтому включается/
выключается одной строкой в `.env`, без правки compose.
1. В `.env`:
   ```ini
   COMPOSE_PROFILES=              # пусто -> локальный ollama НЕ стартует
   OLLAMA_URL=http://<ip-сервера>:11434
   LOCAL_MODEL=<модель на том сервере>
   ```
   (по умолчанию `COMPOSE_PROFILES=local-model` — локальный Ollama поднимается.)
2. Поднимите стек: `docker compose -f docker-compose.lab.yml up -d`.
   Сервис `ollama` пропускается, оркестратор и мишени ходят на внешний адрес.
3. На том сервере Ollama должен слушать `0.0.0.0` (`OLLAMA_HOST=0.0.0.0`), быть
   сетево доступен, и нужная модель — загружена (`ollama pull`).

Обратно на локальный движок — верните `COMPOSE_PROFILES=local-model` и
`OLLAMA_URL=http://ollama:11434`.

**Инструменты и мишени без модели.** Сканеры (nmap, nikto, sqlmap, curl-пробы) —
обычные бинарники, модель им не нужна; без неё падает лишь оркестрованный *анализ*
вывода. Из мишеней модель используют только `vulnllm` и `ragapp` (они сами
LLM-приложения) — им нужен Ollama-совместимый эндпоинт. Остальные 8 мишеней
(web, API, сеть, GraphQL, misconfig, mcppoison) работают без модели. Движок,
отличный от Ollama, подойдёт мишеням только если эмулирует Ollama API (`/api/chat`).

**Важно про ИИ-мишени и облачный API.** Внешний коммерческий ИИ (`ALLOW_EXTERNAL`)
подключён только к оркестратору через санитайзер. Мишени `vulnllm`/`ragapp` умеют
ходить лишь в Ollama-совместимый эндпоинт — им в любом случае нужен доступный
Ollama (локальный или внешний). Без него эти две мишени не работают; остальные 8 —
работают.

---

## 11a. Внешний ИИ по умолчанию (Алиса / YandexGPT и др.)

Разбор вывода и оркестрацию (планирование шагов в pentest, разбор инцидента в
soar) можно по умолчанию направить во **внешний ИИ** — но строго **через
санитайзер**: перед отправкой наружу маскируются IP/хосты/e-mail/секреты, а
ответ размаскировывается обратно. Где что прописывать — только в `.env`
(compose пробрасывает эти переменные в `sanitizer`, `pentest`, `soar`):

```ini
ALLOW_EXTERNAL=true                 # снять жёсткий рубильник наружу
DEFAULT_ROUTE=external              # по умолчанию разбор/оркестрация — внешним ИИ
EXTERNAL_PROVIDER=yandex            # anthropic | yandex | openai
EXTERNAL_URL=https://llm.api.cloud.yandex.net/foundationModels/v1/completion
EXTERNAL_MODEL=yandexgpt/latest     # или yandexgpt-lite/latest, либо gpt://<folder>/<model>
EXTERNAL_API_KEY=<Api-Key сервисного аккаунта Yandex Cloud>
YANDEX_FOLDER_ID=<b1g... id каталога>
```
Затем: `docker compose -f docker-compose.lab.yml up -d` (или `restart sanitizer
pentest`). Проверка: `curl :8020/healthz` и `docker compose ... exec sanitizer` →
у санитайзера `GET /healthz` покажет `provider` и `external_model`.

- **Где взять доступ к «Алисе».** «Алиса» как API — это **YandexGPT** в Yandex
  Cloud (Foundation Models). Нужны: каталог (`folder id`, вид `b1g…`), сервисный
  аккаунт с ролью `ai.languageModels.user` и его **Api-Key**. `modelUri`
  собирается автоматически из `YANDEX_FOLDER_ID` + `EXTERNAL_MODEL`, либо задайте
  целиком (`EXTERNAL_MODEL=gpt://<folder>/yandexgpt/latest`).
- **Провайдеры.** `EXTERNAL_PROVIDER=anthropic` (Claude), `yandex` (Алиса),
  `openai` (любой OpenAI-совместимый эндпоинт, в т.ч. RU-прокси). Формат запроса
  под каждый — внутри санитайзера, менять код не нужно.
- **Точечно, не по умолчанию.** Можно оставить `DEFAULT_ROUTE=local`, а внешний
  ИИ включать галочкой «разбирать вывод внешним ИИ» в панели/CLI per-request.
- **Что уходит наружу.** Только обезличенный текст. НО: PII-детект Presidio
  настроен на английский — русские ФИО/телефоны он ловит хуже; сетевые артефакты
  и секреты маскируются регексами независимо от языка. Это снижение риска, а не
  гарантия. Используйте только тариф с Zero-Data-Retention и opt-out обучения.
- **ИИ-мишени — отдельно.** `vulnllm`/`ragapp` на внешний ИИ НЕ переключаются:
  они эмулируют Ollama-клиента и ходят в `OLLAMA_URL`. Если оркестрацию вынесли
  на Алису и локальный Ollama больше не нужен для анализа — он всё ещё нужен этим
  двум мишеням (иначе они не работают; остальные 8 — работают без модели).

---

## 12. Обслуживание

- **Обновление образов мишеней:**
  `docker compose -f docker-compose.lab.yml pull` затем `up -d`.
- **Смена локальной модели:** поменяйте `LOCAL_MODEL` в `.env`, затем
  `ollama pull <model>` и `restart pentest sanitizer`.
- **Аудит-журналы** в томе `audit` (`/data/audit/*.log`). Для долгого хранения
  пересылайте в SIEM или периодически архивируйте том.
- **Резервная копия конфигурации:** достаточно сохранить `.env`, `engagement/`,
  и любые ваши правки в `targets/`, `tools.py`. Модель и образы восстановимы.
- **Очистка места:** `docker system prune` (осторожно), том `ollama_models`
  крупный (~20 ГБ на модель).

---

## 13. Безопасность эксплуатации

- Полигон рассчитан на **изолированную/локальную** среду. Мишени намеренно уязвимы —
  не публикуйте порты наружу, не поднимайте на машине с доступом в продакшн-сети.
- Всё слушается на `127.0.0.1`. Для доступа с других машин используйте reverse-proxy
  с TLS и аутентификацией — не открывайте порты напрямую.
- `metasploitable` особенно «злая» мишень (реально уязвимые сервисы) — держите её
  строго в `labnet`.
- Секреты только в `.env` (вне git). Не коммитьте реальные токены.
- Внешний ИИ по умолчанию выключен (`ALLOW_EXTERNAL=false`); включайте только с
  тарифом Zero-Data-Retention и понимая, что уходит наружу (санитайзер маскирует
  IP/ПДн/секреты, но это снижение риска, а не гарантия).

Предохранители контура (не зависят от модели): проверка scope, allowlist
инструментов, запрет произвольного shell, подтверждение оператором, аудит.

---

## 14. Диагностика

| Симптом | Причина / решение |
|---|---|
| `healthz` не отвечает | pentest не поднялся: `... ps`, `... logs pentest` |
| 401/403 в API | Неверный/отсутствующий токен; для scope-403 — цель не в allowed_hosts |
| 429 | Rate limit (60/мин на роль), подождать |
| Мишень «down» на панели | Контейнер стартует (Metasploitable/WebGoat дольше) или не поднят |
| Модель падает/OOM | Мало VRAM: `LOCAL_MODEL=qwen2.5:7b` + `ollama pull` + restart |
| llm/rag/ mcp «пусто» | Первый запрос грузит модель; повторить через минуту |
| Панель без стилей (чёрный текст) | Обновить страницу Ctrl+Shift+R; проверить, что `webui/mgts/` на месте |
| dvga не поднимается | Проверить доступность образа `dolevf/dvga` (`... pull dvga`) |

---

## 15. Справочник API (сервис pentest, порт 8020)

Все требуют заголовок `x-api-key: <operator-token>`.

| Метод | Путь | Назначение |
|---|---|---|
| POST | /v1/plan | Модель предлагает следующий шаг |
| POST | /v1/approve | Подтвердить и выполнить предложенный шаг |
| POST | /v1/run | Прямой запуск инструмента (вкладка Arsenal) |
| GET | /v1/tools | Список инструментов allowlist |
| GET | /v1/scope | Активный scope |
| PUT | /v1/scope | Ручное изменение scope в рантайме (**только admin**) |
| GET | /v1/lab/targets | Мишени + статус + учебные цели |
| GET | /v1/audit?limit=N | Последние записи аудита |
| GET | /v1/report/{sid} | Отчёт по сессии (JSON) |
| GET | /v1/report/{sid}/markdown?save=true | Отчёт в Markdown |
| GET | /healthz | Здоровье сервиса |

---

## 16. Быстрый чек-лист перед занятием

- [ ] `docker compose -f docker-compose.lab.yml ps` — все сервисы Up
- [ ] `curl :8020/healthz` — engagement LAB-TRAINING
- [ ] мишени с состоянием сброшены (`ragapp`, при необходимости `dvwa`)
- [ ] веб-панель открывается, точки soar/pentest зелёные
- [ ] у обучающихся есть operator-токен
- [ ] (опц.) аудит-журнал очищен/заархивирован от прошлой сессии

Полигон готов к работе.
