"""Shared pytest fixtures + environment setup for LinkShield tests."""
import os

# Set DEBUG before any api.* imports — prevents crash on missing prod-only env vars
os.environ.setdefault("DEBUG", "true")
os.environ.setdefault("SUPABASE_JWT_SECRET", "test-secret-for-development-only-not-for-production-use")
