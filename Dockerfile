FROM python:3.11-slim

WORKDIR /app

# v3 force rebuild
RUN apt-get update && apt-get install -y --no-install-recommends gcc && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY api/ api/
COPY data/ data/
COPY ml/ ml/
COPY start-server.sh .
RUN chmod +x start-server.sh

RUN useradd -m appuser && chown -R appuser:appuser /app
USER appuser

ENTRYPOINT ["/bin/sh", "/app/start-server.sh"]
