# Contributing to Cleanway

Thank you for your interest in contributing!

## Development Setup

```bash
git clone https://github.com/YOUR_USERNAME/cleanway.git
cd cleanway
cp .env.example .env
pip install -r requirements.txt
make dev  # API on localhost:8000
```

## Project Structure

```
api/           — FastAPI backend (Python)
extension/     — Chrome Extension (Manifest V3, vanilla JS)
extension-firefox/ — Firefox Extension (MV2)
extension-safari/  — Safari Extension
mobile/        — React Native/Expo app (iOS + Android)
landing/       — Next.js landing page
ml/            — ML model training + bloom filter compiler
data/          — Tranco lists, model, brand targets
tests/         — Unit, integration, feature tests
supabase/      — Database migrations
```

## Running Tests

```bash
make test                              # 75 unit tests
python3 -m tests.test_api_integration  # 10 integration tests
python3 -m tests.test_features         # 9 feature tests
python3 -m tests.benchmark_scoring     # Detection rate benchmark
```

## Code Style

- Python: follow PEP 8, use type hints
- JavaScript: no ES modules in extension (MV3 service worker limitation)
- All files: `from __future__ import annotations` for Python 3.9 compatibility

## Privacy Rules

**Never log or store:**
- Full URLs (only domain names)
- User IP addresses
- JWT tokens
- Page content or screenshots

## Pull Request Process

1. Fork the repo
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Write tests for new functionality
4. Run `make test` — all tests must pass
5. Submit PR with description of changes

## Reporting Security Issues

See [SECURITY.md](SECURITY.md)
