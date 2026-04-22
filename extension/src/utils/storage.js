/**
 * On-device storage using IndexedDB.
 *
 * Privacy: ALL browsing data stays on-device.
 * Server never sees: full URLs, check history, audit results.
 *
 * Schema:
 *   checks: { id, url, domain, score, level, reasons, source, checked_at }
 *   settings: { key, value }
 */

const DB_NAME = "cleanway";
const DB_VERSION = 1;

let _db = null;

/**
 * Open or create the IndexedDB database
 */
function openDB() {
  if (_db) return Promise.resolve(_db);

  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);

    request.onupgradeneeded = (event) => {
      const db = event.target.result;

      // Check history store
      if (!db.objectStoreNames.contains("checks")) {
        const store = db.createObjectStore("checks", {
          keyPath: "id",
          autoIncrement: true,
        });
        store.createIndex("domain", "domain", { unique: false });
        store.createIndex("checked_at", "checked_at", { unique: false });
        store.createIndex("level", "level", { unique: false });
      }

      // Settings store
      if (!db.objectStoreNames.contains("settings")) {
        db.createObjectStore("settings", { keyPath: "key" });
      }
    };

    request.onsuccess = (event) => {
      _db = event.target.result;
      resolve(_db);
    };

    request.onerror = () => reject(request.error);
  });
}

/**
 * Save a domain check result to local history
 */
export async function saveCheck(result) {
  const db = await openDB();
  const tx = db.transaction("checks", "readwrite");
  const store = tx.objectStore("checks");

  store.add({
    url: result.url || "",
    domain: result.domain,
    score: result.score,
    level: result.level,
    reasons: result.reasons || [],
    confidence: result.confidence || "medium",
    source: result.cached ? "cache" : "api",
    checked_at: new Date().toISOString(),
  });

  return new Promise((resolve, reject) => {
    tx.oncomplete = resolve;
    tx.onerror = () => reject(tx.error);
  });
}

/**
 * Get recent check history (newest first)
 * @param {number} limit
 */
export async function getRecentChecks(limit = 50) {
  const db = await openDB();
  const tx = db.transaction("checks", "readonly");
  const store = tx.objectStore("checks");
  const index = store.index("checked_at");

  return new Promise((resolve, reject) => {
    const results = [];
    const request = index.openCursor(null, "prev"); // newest first

    request.onsuccess = (event) => {
      const cursor = event.target.result;
      if (cursor && results.length < limit) {
        results.push(cursor.value);
        cursor.continue();
      } else {
        resolve(results);
      }
    };

    request.onerror = () => reject(request.error);
  });
}

/**
 * Get domain check stats for weekly report
 */
export async function getWeeklyStats() {
  const db = await openDB();
  const tx = db.transaction("checks", "readonly");
  const store = tx.objectStore("checks");

  const oneWeekAgo = new Date();
  oneWeekAgo.setDate(oneWeekAgo.getDate() - 7);

  return new Promise((resolve, reject) => {
    const stats = { total: 0, safe: 0, caution: 0, dangerous: 0 };
    const request = store.openCursor();

    request.onsuccess = (event) => {
      const cursor = event.target.result;
      if (cursor) {
        const check = cursor.value;
        if (new Date(check.checked_at) >= oneWeekAgo) {
          stats.total++;
          stats[check.level] = (stats[check.level] || 0) + 1;
        }
        cursor.continue();
      } else {
        resolve(stats);
      }
    };

    request.onerror = () => reject(request.error);
  });
}

/**
 * Save a setting
 */
export async function setSetting(key, value) {
  const db = await openDB();
  const tx = db.transaction("settings", "readwrite");
  tx.objectStore("settings").put({ key, value });
}

/**
 * Get a setting
 */
export async function getSetting(key, defaultValue = null) {
  const db = await openDB();
  const tx = db.transaction("settings", "readonly");
  const request = tx.objectStore("settings").get(key);

  return new Promise((resolve) => {
    request.onsuccess = () => {
      resolve(request.result ? request.result.value : defaultValue);
    };
    request.onerror = () => resolve(defaultValue);
  });
}

/**
 * Clear old checks (older than 30 days)
 */
export async function pruneOldChecks() {
  const db = await openDB();
  const tx = db.transaction("checks", "readwrite");
  const store = tx.objectStore("checks");

  const thirtyDaysAgo = new Date();
  thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

  const request = store.openCursor();
  request.onsuccess = (event) => {
    const cursor = event.target.result;
    if (cursor) {
      if (new Date(cursor.value.checked_at) < thirtyDaysAgo) {
        cursor.delete();
      }
      cursor.continue();
    }
  };
}
