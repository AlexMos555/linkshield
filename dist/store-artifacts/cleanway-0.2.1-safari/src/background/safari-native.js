/**
 * "Seen working in Safari" — the one thing the extension tells the Cleanway
 * app it ships in.
 *
 * Safari runs the extension's native half (SafariWebExtensionHandler in the
 * app's Safari extension target, mobile/plugins/withSafariExtension.js) when
 * the background calls runtime.sendNativeMessage(). That half writes the time
 * into the app group the app shares, and the iPhone app's "Protection on
 * iPhone" card reads it: proof that the extension is switched on AND that
 * Safari let it run on a real web page, which is the step people miss
 * ("Allow on all websites"). iOS 26.2+ also has an API for the switch alone;
 * nothing tells the app about website access except this.
 *
 * What is sent: {type: "seen"}. No site, no link, no time from the page —
 * the native side stamps its own clock. At most once per SEEN_EVERY_MS, so a
 * busy browsing session wakes the native process a handful of times a day.
 *
 * Only in Safari (the base URL is safari-web-extension:) and only where the
 * manifest asks for nativeMessaging (extension-safari/manifest.json); Chrome
 * and Firefox have no such function without that permission, and a Mac's
 * Safari without the app around simply answers with an error that is
 * ignored.
 */

export const SEEN_EVERY_MS = 6 * 3600_000;
export const SEEN_STORAGE_KEY = "safari_seen_sent_at";
// Safari ignores the application id and always talks to the containing app.
const NATIVE_APP_ID = "ai.cleanway.app";

/** True when this sender is a content script on a real web page (top frame or not). */
export function isWebPageSender(sender) {
  const url = sender && sender.tab && typeof sender.url === "string" ? sender.url : "";
  return url.startsWith("https://") || url.startsWith("http://");
}

/** Pure: is it time to tell the app again? */
export function seenIsDue(lastSentMs, nowMs) {
  return !(typeof lastSentMs === "number" && lastSentMs > 0 && nowMs - lastSentMs < SEEN_EVERY_MS && nowMs >= lastSentMs);
}

export function createSafariSeen(api, { now = () => Date.now() } = {}) {
  let base = "";
  try { base = api.runtime.getURL(""); } catch (e) { /* not an extension context */ }
  const available = base.startsWith("safari-web-extension:")
    && Boolean(api.runtime) && typeof api.runtime.sendNativeMessage === "function";
  let inFlight = null;
  let lastSentMs = null; // this worker's memory; storage covers restarts

  async function noteOnce() {
    const t = now();
    if (!seenIsDue(lastSentMs, t)) return false;
    const stored = await api.storage.local.get(SEEN_STORAGE_KEY);
    const persisted = stored ? stored[SEEN_STORAGE_KEY] : null;
    if (!seenIsDue(persisted, t)) {
      lastSentMs = persisted;
      return false;
    }
    const reply = await api.runtime.sendNativeMessage(NATIVE_APP_ID, { type: "seen" });
    if (!reply || reply.ok !== true) return false; // no app around (a Mac without it): try again later
    lastSentMs = t;
    await api.storage.local.set({ [SEEN_STORAGE_KEY]: t });
    return true;
  }

  /** Fire and forget. Resolves true when the app was told just now. */
  function note() {
    if (!available) return Promise.resolve(false);
    if (inFlight) return inFlight;
    inFlight = noteOnce()
      .catch(() => false)
      .finally(() => { inFlight = null; });
    return inFlight;
  }

  return { available, note };
}
