#!/bin/bash
# ═══════════════════════════════════════════════════
# Cleanway — Production Setup
# Run step by step, each section is independent
# ═══════════════════════════════════════════════════

set -e
cd "$(dirname "$0")/.."
ROOT=$(pwd)

echo ""
echo "  🛡️  Cleanway Production Setup"
echo "  ════════════════════════════════"
echo ""

# ── Step 1: Login to services ──
echo "Step 1: Login to services"
echo "─────────────────────────"
echo "Run each command and follow browser prompts:"
echo ""
echo "  railway login"
echo "  vercel login"
echo "  supabase login"
echo ""
read -p "Press Enter when all logins are done..."

# ── Step 2: Create Supabase project ──
echo ""
echo "Step 2: Supabase"
echo "────────────────"
echo "Option A: Create via CLI:"
echo "  supabase projects create cleanway --org-id YOUR_ORG_ID --db-password YOUR_PASSWORD --region us-east-1"
echo ""
echo "Option B: Create at https://supabase.com/dashboard"
echo "  → New Project → name: cleanway → generate password → create"
echo ""
echo "After creating, get these values from Settings → API:"
echo "  SUPABASE_URL=https://xxxx.supabase.co"
echo "  SUPABASE_ANON_KEY=eyJhbG..."
echo "  SUPABASE_SERVICE_KEY=eyJhbG..."
echo "  SUPABASE_JWT_SECRET=your-jwt-secret"
echo ""
read -p "Enter SUPABASE_URL: " SUPABASE_URL
read -p "Enter SUPABASE_ANON_KEY: " SUPABASE_ANON_KEY
read -p "Enter SUPABASE_SERVICE_KEY: " SUPABASE_SERVICE_KEY
read -p "Enter SUPABASE_JWT_SECRET: " SUPABASE_JWT_SECRET

# Run migrations
echo ""
echo "Running database migrations..."
echo "Paste the contents of these files into Supabase SQL Editor:"
echo "  $ROOT/supabase/migrations/001_initial_schema.sql"
echo "  $ROOT/supabase/migrations/002_feedback_reports.sql"
echo ""
read -p "Press Enter when migrations are done..."

# ── Step 3: Deploy API on Railway ──
echo ""
echo "Step 3: Deploy API on Railway"
echo "─────────────────────────────"
cd "$ROOT"

# Create .env for Railway
cat > .env << EOF
DEBUG=false
SUPABASE_URL=$SUPABASE_URL
SUPABASE_ANON_KEY=$SUPABASE_ANON_KEY
SUPABASE_SERVICE_KEY=$SUPABASE_SERVICE_KEY
SUPABASE_JWT_SECRET=$SUPABASE_JWT_SECRET
REDIS_URL=redis://localhost:6379
ALLOWED_ORIGINS=https://cleanway.ai,https://cleanway.vercel.app
EOF

echo "Created .env file"
echo ""
echo "Deploying to Railway..."
railway init --name cleanway-api 2>/dev/null || true
railway up --detach

echo ""
echo "Add Redis plugin:"
echo "  railway add --plugin redis"
echo "  (or add Redis from Railway dashboard)"
echo ""
read -p "Enter Railway API URL (e.g., https://cleanway-api.up.railway.app): " API_URL
echo "API URL: $API_URL"

# ── Step 4: Deploy Landing on Vercel ──
echo ""
echo "Step 4: Deploy Landing on Vercel"
echo "────────────────────────────────"
cd "$ROOT/landing"

# Set API URL for landing
echo "API_URL=$API_URL" > .env.production

vercel --prod --yes

echo ""
read -p "Enter Vercel URL (e.g., https://cleanway.vercel.app): " LANDING_URL
echo "Landing URL: $LANDING_URL"

# ── Step 5: Update extension ──
echo ""
echo "Step 5: Update extension for production"
echo "────────────────────────────────────────"
cd "$ROOT"

# Update API_BASE in background.js
sed -i '' "s|http://localhost:8000|$API_URL|g" extension/src/background/index.js
sed -i '' "s|http://localhost:8000|$API_URL|g" extension/src/popup/popup.js

echo "Updated API_BASE to $API_URL"

# Rebuild zip
cd extension
rm -f ../cleanway-extension.zip
zip -rq ../cleanway-extension.zip . -x "*.md"
cd ..
echo "Extension rebuilt: cleanway-extension.zip"

# ── Step 6: Update CORS ──
echo ""
echo "Step 6: Update CORS origins"
echo "───────────────────────────"
echo "In Railway dashboard, set env var:"
echo "  ALLOWED_ORIGINS=$LANDING_URL,chrome-extension://YOUR_EXTENSION_ID"

# ── Summary ──
echo ""
echo "═══════════════════════════════════════════"
echo "  ✅ PRODUCTION SETUP COMPLETE"
echo "═══════════════════════════════════════════"
echo ""
echo "  API:       $API_URL"
echo "  Landing:   $LANDING_URL"
echo "  Extension: Upload cleanway-extension.zip to Chrome Web Store"
echo ""
echo "  Next steps:"
echo "  1. Upload extension to https://chrome.google.com/webstore/devconsole"
echo "  2. Create Stripe products at https://dashboard.stripe.com/products"
echo "  3. Set STRIPE_SECRET_KEY in Railway env vars"
echo "  4. Buy domain cleanway.ai and point to Vercel"
echo "═══════════════════════════════════════════"
