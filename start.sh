#!/bin/bash
# ═══════════════════════════════════════════════════
# LinkShield — Start Everything
# Usage: ./start.sh
# ═══════════════════════════════════════════════════

set -e
cd "$(dirname "$0")"

echo ""
echo "  🛡️  LinkShield — Starting All Services"
echo "  ═══════════════════════════════════════"
echo ""

# Kill any existing instances
pkill -f "uvicorn api.main" 2>/dev/null || true
pkill -f "next dev" 2>/dev/null || true
sleep 1

# ── 1. Start API ──
echo "  [1/3] Starting API server..."
DEBUG=true nohup python3 -m uvicorn api.main:app --host 127.0.0.1 --port 8000 --reload > /tmp/linkshield-api.log 2>&1 &
API_PID=$!
sleep 3

# Verify API
if curl -s http://127.0.0.1:8000/health > /dev/null 2>&1; then
  echo "        ✅ API running at http://127.0.0.1:8000"
  echo "        📖 Docs at http://127.0.0.1:8000/docs"
else
  echo "        ❌ API failed to start. Check /tmp/linkshield-api.log"
fi

# ── 2. Start Landing ──
echo "  [2/3] Starting landing page..."
cd landing
if [ ! -d "node_modules" ]; then
  npm install --silent 2>/dev/null
fi
nohup npx next dev -p 3000 > /tmp/linkshield-landing.log 2>&1 &
LANDING_PID=$!
cd ..
sleep 3

if curl -s http://127.0.0.1:3000 > /dev/null 2>&1; then
  echo "        ✅ Landing at http://127.0.0.1:3000"
else
  echo "        ⚠️  Landing starting... (check /tmp/linkshield-landing.log)"
fi

# ── 3. Extension ──
echo "  [3/3] Extension ready to install"
echo "        📁 Load from: $(pwd)/extension"
echo ""
echo "        To install in Chrome:"
echo "        1. Open chrome://extensions/"
echo "        2. Enable 'Developer mode' (top right)"
echo "        3. Click 'Load unpacked'"
echo "        4. Select: $(pwd)/extension"

# ── Summary ──
echo ""
echo "  ═══════════════════════════════════════"
echo "  ✅ All services running!"
echo ""
echo "  API:       http://127.0.0.1:8000"
echo "  API Docs:  http://127.0.0.1:8000/docs"
echo "  Landing:   http://127.0.0.1:3000"
echo "  Extension: Load unpacked from ./extension"
echo ""
echo "  Logs:"
echo "    API:     tail -f /tmp/linkshield-api.log"
echo "    Landing: tail -f /tmp/linkshield-landing.log"
echo ""
echo "  Stop all: pkill -f 'uvicorn|next'"
echo "  ═══════════════════════════════════════"
echo ""

# Keep running
wait
