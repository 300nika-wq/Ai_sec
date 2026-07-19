FROM python:3.12-slim AS runtime
WORKDIR /app
RUN useradd --uid 10001 --no-create-home appuser
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
 && python -m spacy download en_core_web_lg || true
COPY app/ ./app/
RUN mkdir -p /data/audit && chown -R 10001 /data
USER 10001
EXPOSE 8000
ENTRYPOINT ["python","-m","uvicorn","app.main:app","--host","0.0.0.0","--port","8000"]
