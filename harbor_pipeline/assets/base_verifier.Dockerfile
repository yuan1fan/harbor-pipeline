FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN apt-get update \
 && apt-get install -y --no-install-recommends bash curl wget ca-certificates passwd \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --create-home --shell /bin/sh replay \
 && mkdir -p /logs/artifacts /logs/verifier /tests

WORKDIR /tests
