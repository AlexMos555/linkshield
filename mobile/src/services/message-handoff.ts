/**
 * Hands a shared message from the share-intent router to the message-check
 * screen — in memory, once.
 *
 * Not a route param on purpose. Params become part of the navigation state
 * and of the deep-link URL expo-router builds for the screen, which is exactly
 * the kind of string that ends up in a log line or a crash breadcrumb. The
 * text of someone's SMS must never be written anywhere, so it travels in this
 * variable instead, and the screen takes it (which clears it) as it mounts.
 *
 * A handoff nobody takes quickly is dropped: if navigation failed, the text
 * must not surface later in a check the person started by hand.
 */

const HANDOFF_TTL_MS = 30_000;

let pending: { text: string; at: number } | null = null;

export function handOffMessage(text: string): void {
  pending = { text, at: Date.now() };
}

/** The handed-off text, at most once; null when there is none or it expired. */
export function takeHandedOffMessage(): string | null {
  const taken = pending;
  pending = null;
  if (!taken || Date.now() - taken.at > HANDOFF_TTL_MS) return null;
  return taken.text;
}
