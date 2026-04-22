-- Migration 007: Pin search_path on functions (Supabase lint fix)
--
-- Fixes Supabase Security Advisor warning:
-- "Function Search Path Mutable — Detects functions where the search_path
--  parameter is not set."
--
-- Why this matters: a function without an explicit search_path resolves
-- unqualified object references using the *caller's* search_path. An
-- attacker who can set their own search_path (or trick a superuser into
-- running the function) can shadow `public.table` with a malicious
-- `attacker_schema.table` and hijack the function's behavior.
--
-- Fix: pin search_path on each flagged function. We use `public, pg_temp`
-- so the function still resolves its own public.* references normally but
-- can't be tricked into resolving them via another schema.

-- public.get_pricing_tier(TEXT) — from migration 003
ALTER FUNCTION public.get_pricing_tier(TEXT) SET search_path = public, pg_temp;

-- public.report_phone(TEXT, TEXT, TEXT, TEXT) — from migration 005
ALTER FUNCTION public.report_phone(TEXT, TEXT, TEXT, TEXT) SET search_path = public, pg_temp;
