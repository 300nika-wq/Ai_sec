#!/usr/bin/env bash
# Последовательное скачивание всех образов стенда с ретраями.
#
# Зачем: `docker compose up` тянет образы ПАРАЛЛЕЛЬНО и упирается в лимит
# анонимных пулов Docker Hub (100/6ч на IP) — тогда один образ падает с
# «not found»/429, а остальные показывают «Interrupted». Здесь тянем по одному
# с повторами, что надёжно обходит троттлинг.
#
# Использование:
#   bash pull-images.sh                 # скачать все образы стенда (lab + webui)
#   RETRIES=10 bash pull-images.sh      # больше попыток на образ
#
# Совет: если лимит всё равно бьётся — `docker login` (лимит поднимется до 200/6ч),
# затем повторите. После успешного pull: docker compose -f docker-compose.lab.yml up -d --build
set -u

RETRIES="${RETRIES:-6}"

IMAGES=(
  # базовые образы для сборки наших сервисов
  "python:3.12-slim-bookworm"
  "python:3.12-slim"
  "nginx:alpine"
  # движок модели
  "ollama/ollama:latest"
  # готовые мишени (сторонние)
  "bkimminich/juice-shop:latest"
  "vulnerables/web-dvwa:latest"
  "webgoat/webgoat:latest"
  "erev0s/vampi:latest"
  "tleemcjr/metasploitable2:latest"
  "dolevf/dvga:latest"
)
# garak собирается на python:3.12-slim (уже в списке) — отдельные образы ему не нужны.

fail=0
for img in "${IMAGES[@]}"; do
  ok=0
  for n in $(seq 1 "$RETRIES"); do
    printf '\n>>> pull %s (попытка %s/%s)\n' "$img" "$n" "$RETRIES"
    if docker pull "$img"; then ok=1; break; fi
    sleep $(( n * 5 ))
  done
  if [ "$ok" -ne 1 ]; then
    echo "!!! не удалось скачать $img после $RETRIES попыток" >&2
    fail=1
  fi
done

if [ "$fail" -eq 0 ]; then
  echo
  echo "Все образы на месте. Теперь:"
  echo "  docker compose -f docker-compose.lab.yml up -d --build"
  echo "  docker compose -f docker-compose.webui.yml up -d"
else
  echo
  echo "Часть образов не скачалась — вероятно лимит Docker Hub." >&2
  echo "Сделайте 'docker login' и запустите скрипт снова." >&2
  exit 1
fi
