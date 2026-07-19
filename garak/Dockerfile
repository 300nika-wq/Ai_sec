FROM python:3.12-slim AS runtime
WORKDIR /app
# git — некоторые зависимости garak ставятся из VCS; ca-certificates — для egress.
RUN apt-get update && apt-get install -y --no-install-recommends \
      git ca-certificates \
 && rm -rf /var/lib/apt/lists/*
RUN useradd --uid 10001 --no-create-home appuser
COPY requirements.txt .
# Ставим garak (тянет torch/transformers — долго и объёмно, это ожидаемо).
RUN pip install --no-cache-dir -r requirements.txt
COPY app/ ./
COPY _security.py ./app_security.py
RUN mkdir -p /data/garak /data/audit /data/hf /data/cache && chown -R 10001 /data
USER 10001
# Кэши моделей/детекторов garak — на пишущий том /data (rootfs не read-only: garak
# может докачивать модели детекторов при первом запуске).
ENV HOME=/data HF_HOME=/data/hf XDG_CACHE_HOME=/data/cache \
    GARAK_REPORTS_DIR=/data/garak
EXPOSE 8030
ENTRYPOINT ["python","-m","uvicorn","main:app","--host","0.0.0.0","--port","8030"]
