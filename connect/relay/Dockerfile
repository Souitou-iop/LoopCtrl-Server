# LoopCtrl relay: standard-library Python, no dependencies.
#   docker build -t loopctrl-relay connect/relay
FROM python:3.12-slim

LABEL org.opencontainers.image.title="loopctrl-relay" \
      org.opencontainers.image.description="LoopCtrl in-app relay: invite enrollment and a long-poll transport for LoopCtrl's JSON-RPC" \
      org.opencontainers.image.source="https://github.com/Souitou-iop/LoopCtrl-Server" \
      org.opencontainers.image.licenses="Apache-2.0"

RUN useradd --system --uid 10001 --no-create-home --home-dir /data relay \
 && install -d -o relay -g relay -m 0700 /data

WORKDIR /app
COPY loopctrl_relay_server.py ed25519.py ./

USER relay
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    LOOPCTRL_RELAY_STATE_FILE=/data/state.json
VOLUME ["/data"]
EXPOSE 8787

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8787/healthz', timeout=4)"]

ENTRYPOINT ["python", "/app/loopctrl_relay_server.py", "--bind", "0.0.0.0", "--port", "8787"]
