/**
 * On-device SQLite database.
 * ALL browsing data stays here — never sent to server.
 *
 * Tables:
 *   checks: URL check history (full URL, domain, score, reasons)
 *   audits: Privacy Audit results
 *   settings: User preferences
 */

import * as SQLite from "expo-sqlite";

let db: SQLite.SQLiteDatabase | null = null;

export async function getDB(): Promise<SQLite.SQLiteDatabase> {
  if (!db) {
    db = await SQLite.openDatabaseAsync("linkshield.db");
    await initDB(db);
  }
  return db;
}

async function initDB(db: SQLite.SQLiteDatabase) {
  await db.execAsync(`
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

    CREATE INDEX IF NOT EXISTS idx_checks_domain ON checks(domain);
    CREATE INDEX IF NOT EXISTS idx_checks_date ON checks(checked_at);

    CREATE TABLE IF NOT EXISTS audits (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      domain TEXT NOT NULL,
      grade TEXT NOT NULL,
      trackers INTEGER DEFAULT 0,
      cookies INTEGER DEFAULT 0,
      sensitive_fields INTEGER DEFAULT 0,
      fingerprinting INTEGER DEFAULT 0,
      scanned_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT
    );
  `);
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
  const db = await getDB();
  await db.runAsync(
    `INSERT INTO checks (url, domain, score, level, reasons, confidence, source)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [
      check.url || "",
      check.domain,
      check.score,
      check.level,
      JSON.stringify(check.reasons || []),
      check.confidence || "medium",
      check.source || "api",
    ]
  );
}

export async function getRecentChecks(limit = 50) {
  const db = await getDB();
  const rows = await db.getAllAsync(
    `SELECT * FROM checks ORDER BY checked_at DESC LIMIT ?`,
    [limit]
  );
  return rows.map((r: any) => ({
    ...r,
    reasons: JSON.parse(r.reasons || "[]"),
  }));
}

export async function getStats() {
  const db = await getDB();
  const total = await db.getFirstAsync<{ count: number }>(
    `SELECT COUNT(*) as count FROM checks`
  );
  const blocked = await db.getFirstAsync<{ count: number }>(
    `SELECT COUNT(*) as count FROM checks WHERE level = 'dangerous'`
  );
  const warned = await db.getFirstAsync<{ count: number }>(
    `SELECT COUNT(*) as count FROM checks WHERE level = 'caution'`
  );
  return {
    total_checks: total?.count || 0,
    threats_blocked: blocked?.count || 0,
    threats_warned: warned?.count || 0,
  };
}

export async function getWeeklyStats() {
  const db = await getDB();
  const weekAgo = new Date(Date.now() - 7 * 86400000).toISOString();
  const total = await db.getFirstAsync<{ count: number }>(
    `SELECT COUNT(*) as count FROM checks WHERE checked_at >= ?`,
    [weekAgo]
  );
  const blocked = await db.getFirstAsync<{ count: number }>(
    `SELECT COUNT(*) as count FROM checks WHERE level = 'dangerous' AND checked_at >= ?`,
    [weekAgo]
  );
  return {
    total_checks: total?.count || 0,
    threats_blocked: blocked?.count || 0,
  };
}

// ── Settings ──

export async function getSetting(key: string, defaultValue: string = ""): Promise<string> {
  const db = await getDB();
  const row = await db.getFirstAsync<{ value: string }>(
    `SELECT value FROM settings WHERE key = ?`,
    [key]
  );
  return row?.value || defaultValue;
}

export async function setSetting(key: string, value: string) {
  const db = await getDB();
  await db.runAsync(
    `INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)`,
    [key, value]
  );
}

// ── Cleanup ──

export async function pruneOldChecks(days = 30) {
  const db = await getDB();
  const cutoff = new Date(Date.now() - days * 86400000).toISOString();
  await db.runAsync(`DELETE FROM checks WHERE checked_at < ?`, [cutoff]);
}
