FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir fastapi uvicorn
COPY api/main_minimal.py api/main_minimal.py
CMD ["uvicorn", "api.main_minimal:app", "--host", "0.0.0.0", "--port", "8000"]
