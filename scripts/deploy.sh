#!/bin/bash
# ═══════════════════════════════════════════════════
# LinkShield — Full Deploy Script
# Run: chmod +x scripts/deploy.sh && ./scripts/deploy.sh
# ═══════════════════════════════════════════════════

set -e
echo "🛡️  LinkShield Deploy"
echo "===================="

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# ── Pre-flight checks ──
echo -e "\n${YELLOW}Pre-flight checks...${NC}"

check_cmd() {
    if ! command -v "$1" &> /dev/null; then
        echo -e "${RED}✗ $1 not installed. Install it first.${NC}"
        exit 1
    fi
    echo -e "${GREEN}✓ $1 found${NC}"
}

check_cmd python3
check_cmd node
check_cmd npm

# Optional tools
for cmd in railway vercel supabase; do
    if command -v "$cmd" &> /dev/null; then
        echo -e "${GREEN}✓ $cmd found${NC}"
    else
        echo -e "${YELLOW}⚠ $cmd not found (install: npm i -g $cmd)${NC}"
    fi
done

# ── Check .env ──
echo -e "\n${YELLOW}Checking .env...${NC}"
if [ ! -f .env ]; then
    echo -e "${RED}✗ .env not found. Copy .env.example to .env and fill values.${NC}"
    echo "  cp .env.example .env"
    exit 1
fi
echo -e "${GREEN}✓ .env exists${NC}"

# Check critical vars
for var in SUPABASE_JWT_SECRET SUPABASE_URL REDIS_URL; do
    if grep -q "^${var}=.\+" .env; then
        echo -e "${GREEN}✓ $var is set${NC}"
    else
        echo -e "${YELLOW}⚠ $var is empty or not set${NC}"
    fi
done

# ── Run tests ──
echo -e "\n${YELLOW}Running tests...${NC}"
python3 -m tests.test_scoring 2>&1 | tail -1

# ── Build landing ──
echo -e "\n${YELLOW}Building landing page...${NC}"
cd landing
npm install --silent 2>/dev/null
npx next build 2>&1 | tail -3
cd ..

# ── Deploy steps ──
echo -e "\n${YELLOW}====================================${NC}"
echo -e "${YELLOW}Deploy Checklist (manual steps):${NC}"
echo -e "${YELLOW}====================================${NC}"
echo ""
echo "1. Deploy API to Railway:"
echo "   railway login"
echo "   railway up"
echo ""
echo "2. Add Redis (Upstash):"
echo "   railway add --plugin redis"
echo "   # Or: https://upstash.com → create Redis → copy URL to .env"
echo ""
echo "3. Deploy landing to Vercel:"
echo "   cd landing && vercel --prod"
echo ""
echo "4. Setup Supabase:"
echo "   supabase login"
echo "   supabase db push"
echo "   # Or: paste supabase/migrations/001_*.sql into SQL Editor"
echo ""
echo "5. Setup Stripe:"
echo "   # Create products at https://dashboard.stripe.com/products"
echo "   # Personal Monthly: \$4.99"
echo "   # Personal Yearly: \$49.99"
echo "   # Family Monthly: \$9.99"
echo "   # Family Yearly: \$99.99"
echo "   # Copy price IDs to api/routers/payments.py"
echo "   # Set STRIPE_SECRET_KEY and STRIPE_WEBHOOK_SECRET in .env"
echo ""
echo "6. Update extension:"
echo "   # Set API_BASE in extension/src/background/index.js"
echo "   # Set ALLOWED_ORIGINS in .env (include extension ID)"
echo "   # Re-zip: cd extension && zip -r ../linkshield.zip ."
echo ""
echo "7. Submit to Chrome Web Store:"
echo "   # https://chrome.google.com/webstore/devconsole"
echo "   # Upload linkshield-extension.zip"
echo "   # Fill listing from extension/STORE_LISTING.md"
echo ""
echo -e "${GREEN}Done! All code is built and ready.${NC}"
