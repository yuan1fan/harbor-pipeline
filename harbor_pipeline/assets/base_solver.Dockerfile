FROM node:24-bookworm-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      bash curl ca-certificates procps python3 passwd ripgrep git \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --create-home --shell /bin/sh replay \
 && mkdir -p /workspace /logs/artifacts

# Harbor's claude-code agent checks `command -v claude` before installing its
# runtime. Baking the CLI into the image skips a slow apt/npm setup on every
# solver trial. Keep this version aligned with the host CLI.
RUN npm install -g @anthropic-ai/claude-code@2.1.270

WORKDIR /workspace
