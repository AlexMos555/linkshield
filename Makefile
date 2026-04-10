# LinkShield — Common Commands

.PHONY: dev test benchmark build deploy extension landing

# ── Development ──

dev:  ## Start API locally (debug mode)
	DEBUG=true python3 -m uvicorn api.main:app --reload --host 127.0.0.1 --port 8000

dev-docker:  ## Start API + Redis via Docker
	docker-compose up --build

# ── Testing ──

test:  ## Run all unit tests
	python3 -m tests.test_scoring

benchmark:  ## Run detection rate benchmark
	python3 -m tests.benchmark_scoring

# ── ML ──

train:  ## Train/retrain CatBoost model
	python3 -m ml.train_model

bloom:  ## Compile bloom filter for extension
	python3 -m ml.bloom_compiler

# ── Build ──

build-landing:  ## Build Next.js landing page
	cd landing && npm install && npx next build

build-extension:  ## Package extension for Chrome Web Store
	cd extension && zip -r ../linkshield-extension.zip . -x "*.md" "STORE_LISTING.md"
	@echo "Extension packaged: linkshield-extension.zip"

build-docker:  ## Build Docker image
	docker build -t linkshield-api .

# ── Deploy ──

deploy:  ## Run full deploy checklist
	bash scripts/deploy.sh

# ── Misc ──

lint:  ## Run linter
	ruff check api/ tests/ ml/ --select E,F,W

clean:  ## Clean build artifacts
	rm -rf landing/.next landing/node_modules __pycache__ **/__pycache__
	rm -f linkshield-extension.zip

help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'
