#!/bin/sh
PORT="${PORT:-8000}"
echo "Starting LinkShield API on port $PORT"
exec uvicorn api.main:app --host 0.0.0.0 --port "$PORT"
