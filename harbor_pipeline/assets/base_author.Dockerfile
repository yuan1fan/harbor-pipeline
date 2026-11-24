FROM node:24-bookworm-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      bash sudo curl ca-certificates git ripgrep jq procps unzip zip \
      python3 python3-venv python3-pip build-essential cmake pkg-config \
      iptables netcat-openbsd \
 && rm -rf /var/lib/apt/lists/* \
 && printf 'node ALL=(ALL) NOPASSWD: ALL\n' > /etc/sudoers.d/author \
 && chmod 0440 /etc/sudoers.d/author \
 && mkdir -p /workspace /opt/harbor \
 && chown node:node /workspace
RUN npm install -g @anthropic-ai/claude-code@2.1.270
COPY author_client.py /usr/local/bin/harbor-author
COPY author_net.py /opt/harbor/author_net.py
COPY author_capture.py /opt/harbor/author_capture.py
RUN chmod 0755 /usr/local/bin/harbor-author
USER node
WORKDIR /workspace
ENTRYPOINT ["sleep", "infinity"]
