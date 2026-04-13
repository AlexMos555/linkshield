FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends gcc && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY api/ api/
COPY data/ data/
COPY ml/ ml/
RUN useradd -m appuser && chown -R appuser:appuser /app
USER appuser
EXPOSE 8000
CMD ["python", "-c", "import os; port = os.environ.get('PORT', '8000'); os.execvp('uvicorn', ['uvicorn', 'api.main:app', '--host', '0.0.0.0', '--port', port])"]
