"""
НАМЕРЕННО УЯЗВИМАЯ мишень «облачный/секретный мисконфиг». ТОЛЬКО для лаборатории.
Все данные ФЕЙКОВЫЕ. Демонстрирует:
  - утечку секретов через открытые пути (.env, .git/config, /debug);
  - SSRF-к-метаданным облака (симуляция IMDS с фейковыми credentials);
  - открытый .git (раскрытие исходников/истории).
Ничего опасного не деплоится — это статичные заглушки.
"""
from fastapi import FastAPI
from fastapi.responses import PlainTextResponse, JSONResponse, HTMLResponse

app = FastAPI(title="Misconfig Target (LAB ONLY)")

FAKE_ENV = (
    "DATABASE_URL=postgres://admin:S3cr3tP@ss@db:5432/prod\n"
    "AWS_ACCESS_KEY_ID=AKIAFAKELAB000EXAMPLE\n"
    "AWS_SECRET_ACCESS_KEY=fakeLAB/secret/EXAMPLEkey0000000000000000\n"
    "JWT_SECRET=lab-demo-jwt-secret-do-not-use\n"
)

@app.get("/.env", response_class=PlainTextResponse)
async def dotenv(): return FAKE_ENV  # УЯЗВИМО: секреты в открытом доступе

@app.get("/.git/config", response_class=PlainTextResponse)
async def gitconfig():  # УЯЗВИМО: открытый .git -> раскрытие исходников/истории
    return ("[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n"
            "\turl = https://git.internal.lab/acme/backend.git\n")

@app.get("/debug")
async def debug():  # УЯЗВИМО: debug-эндпоинт с чувствительными данными
    return JSONResponse({"env": "production", "secret_token": "lab-debug-TOKEN-123",
                         "db_password": "S3cr3tP@ss"})

# --- симуляция облачной metadata-службы (IMDS) для практики SSRF ---
@app.get("/latest/meta-data/iam/security-credentials/", response_class=PlainTextResponse)
async def imds_role(): return "lab-app-role"

@app.get("/latest/meta-data/iam/security-credentials/lab-app-role")
async def imds_creds():  # УЯЗВИМО: доступ к временным ключам через SSRF на IMDS
    return JSONResponse({"AccessKeyId": "ASIAFAKELAB000EXAMPLE",
                         "SecretAccessKey": "fakeLAB/imds/EXAMPLEkey000000000000",
                         "Token": "FAKE-IMDS-SESSION-TOKEN", "Expiration": "2030-01-01T00:00:00Z"})

@app.get("/healthz")
async def healthz(): return {"status": "ok", "note": "intentionally misconfigured (lab only)"}

@app.get("/", response_class=HTMLResponse)
async def index():
    return ("<h2>ACME Internal (LAB — намеренно уязвимо)</h2>"
            "<p>Найдите утечки: попробуйте /.env, /.git/config, /debug, "
            "/latest/meta-data/iam/security-credentials/</p>")
