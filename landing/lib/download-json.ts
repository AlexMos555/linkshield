/**
 * "Download my data" on /account: the export (GET /api/v1/user/export) is
 * fetched with the session token like every account call, so it can't be a
 * plain link — the JSON is handed to the browser as a file instead.
 */

/** cleanway-data-2026-10-22.json — the date the copy was made (UTC). */
export function exportFileName(now: Date): string {
  return `cleanway-data-${now.toISOString().slice(0, 10)}.json`;
}

/** Save `data` as a pretty-printed JSON file through a temporary blob link. */
export function saveJsonFile(data: unknown, fileName: string): void {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = fileName;
  link.rel = "noopener";
  document.body.appendChild(link);
  link.click();
  link.remove();
  // Revoked on the next tick: the click has started the download by then.
  setTimeout(() => URL.revokeObjectURL(url), 0);
}
