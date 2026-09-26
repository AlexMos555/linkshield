/**
 * On-device storage.
 * Uses SQLite on native (iOS/Android), falls back to in-memory on web.
 * ALL browsing data stays here — never sent to server.
 */

import { Platform } from "react-native";
import { MESSAGE_CHECK_SOURCE, splitHosts } from "../utils/history-model";

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
    // Do NOT flip _isNative here. One transient open failure (a locked file
    // during an OS restore, low disk at the wrong moment) used to latch the
    // whole app into in-memory storage until the process died — every check
    // from then on was silently lost on exit while history looked fine.
    // Fail this call, try again next call.
    console.warn("SQLite open failed, falling back to memory for this call:", e);
    return null;
  }
}

// ── Check History ──

/** SQL: the row is not a message check (older rows may have no source at all). */
const NOT_MESSAGE = "COALESCE(source, '') != ?";

/** Saves one history row; resolves with its id, or null if it could not be stored. */
export async function saveCheck(check: {
  url?: string;
  domain: string;
  score: number;
  level: string;
  reasons?: any[];
  confidence?: string;
  source?: string;
}): Promise<number | null> {
  const entry = {
    ...check,
    id: Date.now(),
    reasons: check.reasons || [],
    checked_at: new Date().toISOString(),
  };

  const db = await getDB();
  if (db) {
    try {
      const result = await db.runAsync(
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
      return result.lastInsertRowId;
    } catch (e) {
      console.warn("SQLite write failed:", e);
    }
  }

  // Fallback: in-memory
  _memoryChecks.unshift(entry);
  if (_memoryChecks.length > 200) _memoryChecks = _memoryChecks.slice(0, 200);
  return entry.id;
}

/** `source` of the history rows written by the message check (app/message.tsx). */
export { MESSAGE_CHECK_SOURCE };

type MessageCheckRow = { hosts: string[]; level: string; reasons: string[] };

/**
 * One history row per message check, WITHOUT the message: the text is never
 * stored, and neither is any link's path or query (they carry tokens).
 *
 * Row shape: level = the verdict ("dangerous" | "caution" | "no_signals",
 * never "safe"; getStats counts every message check as "checked" only);
 * reasons = the reason codes; domain = the link hosts, space-separated
 * (hosts cannot contain spaces), empty for a message without links; score 0,
 * because a message verdict is not a number. Read the hosts back with
 * messageCheckHosts(). Resolves with the row id, so a later "check the links
 * again" updates this row instead of adding a second one.
 */
export async function saveMessageCheck(entry: MessageCheckRow): Promise<number | null> {
  return saveCheck({
    domain: entry.hosts.join(" "),
    score: 0,
    level: entry.level,
    reasons: entry.reasons,
    source: MESSAGE_CHECK_SOURCE,
  });
}

/** The same message checked again (its links re-asked): rewrite its row, never add one. */
export async function updateMessageCheck(id: number, entry: MessageCheckRow): Promise<void> {
  const reasons = JSON.stringify(entry.reasons);
  const domain = entry.hosts.join(" ");
  const db = await getDB();
  if (db) {
    try {
      await db.runAsync(
        `UPDATE checks SET domain = ?, level = ?, reasons = ? WHERE id = ? AND source = ?`,
        [domain, entry.level, reasons, id, MESSAGE_CHECK_SOURCE],
      );
      return;
    } catch (e) {
      console.warn("SQLite update failed:", e);
    }
  }
  _memoryChecks = _memoryChecks.map((c) =>
    c.id === id && c.source === MESSAGE_CHECK_SOURCE ? { ...c, domain, level: entry.level, reasons: entry.reasons } : c,
  );
}

export function messageCheckHosts(row: { domain?: string }): string[] {
  return splitHosts(row.domain);
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

/**
 * The home activity counters. A message check counts under "checked" only:
 * nothing was blocked — the person was told what the message looks like —
 * and "Blocked 2" after pasting two scam SMS would teach that Cleanway blocks
 * SMS on its own, which it does not.
 */
export async function getStats() {
  const db = await getDB();
  if (db) {
    try {
      const total = await db.getFirstAsync<{ count: number }>(`SELECT COUNT(*) as count FROM checks`);
      const blocked = await db.getFirstAsync<{ count: number }>(
        `SELECT COUNT(*) as count FROM checks WHERE level = 'dangerous' AND ${NOT_MESSAGE}`, [MESSAGE_CHECK_SOURCE],
      );
      const warned = await db.getFirstAsync<{ count: number }>(
        `SELECT COUNT(*) as count FROM checks WHERE level = 'caution' AND ${NOT_MESSAGE}`, [MESSAGE_CHECK_SOURCE],
      );
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
  const links = _memoryChecks.filter(c => c.source !== MESSAGE_CHECK_SOURCE);
  return {
    total_checks: _memoryChecks.length,
    threats_blocked: links.filter(c => c.level === "dangerous").length,
    threats_warned: links.filter(c => c.level === "caution").length,
  };
}

/** The weekly report is about links ("Проверено ссылок"); message checks are not links. */
export async function getWeeklyStats() {
  const weekAgo = Date.now() - 7 * 86400000;
  const db = await getDB();
  if (db) {
    try {
      const cutoff = new Date(weekAgo).toISOString();
      const total = await db.getFirstAsync<{ count: number }>(
        `SELECT COUNT(*) as count FROM checks WHERE checked_at >= ? AND ${NOT_MESSAGE}`, [cutoff, MESSAGE_CHECK_SOURCE],
      );
      const blocked = await db.getFirstAsync<{ count: number }>(
        `SELECT COUNT(*) as count FROM checks WHERE level = 'dangerous' AND checked_at >= ? AND ${NOT_MESSAGE}`,
        [cutoff, MESSAGE_CHECK_SOURCE],
      );
      return { total_checks: total?.count || 0, threats_blocked: blocked?.count || 0 };
    } catch (e) {}
  }

  // Fallback
  const recent = _memoryChecks.filter(
    c => c.source !== MESSAGE_CHECK_SOURCE && new Date(c.checked_at).getTime() >= weekAgo,
  );
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
      // 'localtime': checked_at is stored as ISO UTC, and grouping by the UTC
      // date puts an evening check on "tomorrow" for everyone east of
      // Greenwich and a morning check on "yesterday" west of it — a user in
      // the Americas checking at 20:00 two nights running was told they
      // checked on FOUR days. The user's idea of "a day" is local.
      const row = await db.getFirstAsync<{ days: number }>(
        `SELECT COUNT(DISTINCT date(checked_at, 'localtime')) as days FROM checks WHERE checked_at >= ?`,
        [cutoff]
      );
      return Math.min(7, row?.days || 0);
    } catch (e) {}
  }

  // Fallback — same local-day rule as the SQL path.
  const recent = _memoryChecks.filter(c => new Date(c.checked_at).getTime() >= weekAgo);
  const localDay = (iso: string) => {
    const d = new Date(iso);
    return `${d.getFullYear()}-${d.getMonth()}-${d.getDate()}`;
  };
  return Math.min(7, new Set(recent.map(c => localDay(c.checked_at))).size);
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
