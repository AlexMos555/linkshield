/**
 * On-device storage.
 * Uses SQLite on native (iOS/Android), falls back to in-memory on web.
 * ALL browsing data stays here — never sent to server.
 */

import { Platform } from "react-native";

// In-memory fallback for web (SQLite is native-only)
let _memoryChecks: any[] = [];
let _memorySettings: Record<string, string> = {};
let _isNative = Platform.OS !== "web";
type SQLiteDB = import("expo-sqlite").SQLiteDatabase;

let _db: SQLiteDB | null = null;

async function getDB(): Promise<SQLiteDB | null> {
  if (!_isNative) return null;
  if (_db) return _db;

  try {
    const SQLite = require("expo-sqlite") as typeof import("expo-sqlite");
    _db = await SQLite.openDatabaseAsync("cleanway.db");
    await _db.execAsync(`
      CREATE TABLE IF NOT EXISTS checks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT,
        domain TEXT NOT NULL,
        score INTEGER NOT NULL,
        level TEXT NOT NULL,
        reasons TEXT,
        confidence TEXT DEFAULT 'medium',
        source TEXT DEFAULT 'api',
        checked_at TEXT DEFAULT (datetime('now'))
      );
      CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT
      );
    `);
    return _db;
  } catch (e) {
    console.warn("SQLite unavailable, using in-memory storage:", e);
    _isNative = false;
    return null;
  }
}

// ── Check History ──

export async function saveCheck(check: {
  url?: string;
  domain: string;
  score: number;
  level: string;
  reasons?: any[];
  confidence?: string;
  source?: string;
}) {
  const entry = {
    ...check,
    id: Date.now(),
    reasons: check.reasons || [],
    checked_at: new Date().toISOString(),
  };

  const db = await getDB();
  if (db) {
    try {
      await db.runAsync(
        // checked_at is written explicitly rather than left to the column
        // default. datetime('now') produces "YYYY-MM-DD HH:MM:SS", but every
        // range query below compares against an ISO string with a "T" — and
        // ' ' sorts before 'T', so every check made on the cutoff day itself
        // was silently excluded from the weekly stats. Writing ISO here makes
        // the SQLite rows, the in-memory fallback and the cutoffs one format.
        // Older rows stay readable: parseCheckedAt in history.tsx and
        // SQLite's own date() both accept the legacy shape.
        `INSERT INTO checks (url, domain, score, level, reasons, confidence, source, checked_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          check.url || "",
          check.domain,
          check.score,
          check.level,
          JSON.stringify(check.reasons || []),
          check.confidence || "medium",
          check.source || "api",
          entry.checked_at,
        ]
      );
      return;
    } catch (e) {
      console.warn("SQLite write failed:", e);
    }
  }

  // Fallback: in-memory
  _memoryChecks.unshift(entry);
  if (_memoryChecks.length > 200) _memoryChecks = _memoryChecks.slice(0, 200);
}

export async function getRecentChecks(limit = 50): Promise<any[]> {
  const db = await getDB();
  if (db) {
    try {
      const rows = await db.getAllAsync(
        `SELECT * FROM checks ORDER BY checked_at DESC LIMIT ?`,
        [limit]
      );
      return rows.map((r: any) => ({
        ...r,
        reasons: JSON.parse(r.reasons || "[]"),
      }));
    } catch (e) {
      console.warn("SQLite read failed:", e);
    }
  }

  // Fallback: in-memory
  return _memoryChecks.slice(0, limit);
}

export async function getStats() {
  const db = await getDB();
  if (db) {
    try {
      const total = await db.getFirstAsync<{ count: number }>(`SELECT COUNT(*) as count FROM checks`);
      const blocked = await db.getFirstAsync<{ count: number }>(`SELECT COUNT(*) as count FROM checks WHERE level = 'dangerous'`);
      const warned = await db.getFirstAsync<{ count: number }>(`SELECT COUNT(*) as count FROM checks WHERE level = 'caution'`);
      return {
        total_checks: total?.count || 0,
        threats_blocked: blocked?.count || 0,
        threats_warned: warned?.count || 0,
      };
    } catch (e) {
      console.warn("SQLite stats failed:", e);
    }
  }

  // Fallback: in-memory
  return {
    total_checks: _memoryChecks.length,
    threats_blocked: _memoryChecks.filter(c => c.level === "dangerous").length,
    threats_warned: _memoryChecks.filter(c => c.level === "caution").length,
  };
}

export async function getWeeklyStats() {
  const weekAgo = Date.now() - 7 * 86400000;
  const db = await getDB();
  if (db) {
    try {
      const cutoff = new Date(weekAgo).toISOString();
      const total = await db.getFirstAsync<{ count: number }>(`SELECT COUNT(*) as count FROM checks WHERE checked_at >= ?`, [cutoff]);
      const blocked = await db.getFirstAsync<{ count: number }>(`SELECT COUNT(*) as count FROM checks WHERE level = 'dangerous' AND checked_at >= ?`, [cutoff]);
      return { total_checks: total?.count || 0, threats_blocked: blocked?.count || 0 };
    } catch (e) {}
  }

  // Fallback
  const recent = _memoryChecks.filter(c => new Date(c.checked_at).getTime() >= weekAgo);
  return {
    total_checks: recent.length,
    threats_blocked: recent.filter(c => c.level === "dangerous").length,
  };
}

/**
 * Distinct days (0-7) on which the user checked at least one link in the last
 * week.
 *
 * This is the whole habit score on the Score tab: a counted fact with an exact
 * meaning, not a weighted formula. Days are grouped in UTC, so a check made
 * just before local midnight can land on the neighbouring day — being one
 * boundary off on a habit meter is acceptable; inventing the number is not.
 */
export async function getActiveDaysThisWeek(): Promise<number> {
  const weekAgo = Date.now() - 7 * 86400000;
  const db = await getDB();
  if (db) {
    try {
      const cutoff = new Date(weekAgo).toISOString();
      const row = await db.getFirstAsync<{ days: number }>(
        `SELECT COUNT(DISTINCT date(checked_at)) as days FROM checks WHERE checked_at >= ?`,
        [cutoff]
      );
      return Math.min(7, row?.days || 0);
    } catch (e) {}
  }

  // Fallback
  const recent = _memoryChecks.filter(c => new Date(c.checked_at).getTime() >= weekAgo);
  return Math.min(7, new Set(recent.map(c => c.checked_at.slice(0, 10))).size);
}

// ── Settings ──

export async function getSetting(key: string, defaultValue: string = ""): Promise<string> {
  const db = await getDB();
  if (db) {
    try {
      const row = await db.getFirstAsync<{ value: string }>(`SELECT value FROM settings WHERE key = ?`, [key]);
      return row?.value || defaultValue;
    } catch (e) {}
  }
  return _memorySettings[key] || defaultValue;
}

export async function setSetting(key: string, value: string) {
  const db = await getDB();
  if (db) {
    try {
      await db.runAsync(`INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)`, [key, value]);
      return;
    } catch (e) {}
  }
  _memorySettings[key] = value;
}

// ── Cleanup ──

export async function pruneOldChecks(days = 30) {
  const db = await getDB();
  if (db) {
    try {
      const cutoff = new Date(Date.now() - days * 86400000).toISOString();
      await db.runAsync(`DELETE FROM checks WHERE checked_at < ?`, [cutoff]);
      return;
    } catch (e) {}
  }
  // Fallback
  if (days === 0) {
    _memoryChecks = [];
  } else {
    const cutoff = Date.now() - days * 86400000;
    _memoryChecks = _memoryChecks.filter(c => new Date(c.checked_at).getTime() >= cutoff);
  }
}
