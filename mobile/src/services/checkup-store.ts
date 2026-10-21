/**
 * What the "Проверка защиты" screen remembers — on this phone only.
 *
 * Two things, both in expo-secure-store (encrypted with a key in the
 * phone's keystore, and — unlike SharedPreferences — left out of Android's
 * cloud backup, see docs/PRIVACY.md):
 *  - the family steps the person marked "done";
 *  - the saved "Позвонить близкому" contact: a name and a number.
 *
 * On Android the number (not the name) is also mirrored into the native
 * module's no-backup file (CloseContact.kt, via setCloseContactPhone), so
 * the call guard's stop screen and after-call notice can offer "Позвонить
 * близкому" where JS is not running. Same posture: on the phone only, never
 * in a backup.
 *
 * Nothing here is sent anywhere, synced to an account or logged. Reads are
 * re-validated (utils/checkup.ts): storage is not trusted to hold what we
 * wrote, and a broken value reads as "nothing saved", never as a crash.
 */
import { Platform } from "react-native";
import * as SecureStore from "expo-secure-store";

import { closeContactPhone, setCloseContactPhone } from "../../modules/cleanway-vpn";
import {
  closeContactMirror, parseCloseOne, parseMarks, type CloseOne, type FamilyStepId,
} from "../utils/checkup";

const MARKS_KEY = "checkup_marks";
const CLOSE_ONE_KEY = "checkup_close_one";

async function read(key: string): Promise<string | null> {
  try {
    return await SecureStore.getItemAsync(key);
  } catch {
    return null;
  }
}

/** False when the value could not be stored — the caller says so, not "saved". */
async function write(key: string, value: string | null): Promise<boolean> {
  try {
    if (value === null) await SecureStore.deleteItemAsync(key);
    else await SecureStore.setItemAsync(key, value);
    return true;
  } catch {
    return false;
  }
}

let mirrorWarned = false;

/**
 * Copy the number to the native side (null clears it). Best effort: iOS has
 * no native copy, and an older Android build lacks the function — the in-app
 * buttons still work from secure-store then. Logged once, never the number.
 */
function mirrorToNative(number: string | null): boolean {
  if (Platform.OS !== "android") return true;
  const ok = setCloseContactPhone(number);
  if (!ok && !mirrorWarned) {
    mirrorWarned = true;
    console.warn("checkup: the close-one number could not be mirrored to the native side (older build?)");
  }
  return ok;
}

export async function loadMarks(): Promise<FamilyStepId[]> {
  return parseMarks(await read(MARKS_KEY));
}

export function saveMarks(marks: readonly FamilyStepId[]): Promise<boolean> {
  return write(MARKS_KEY, JSON.stringify(marks));
}

export async function loadCloseOne(): Promise<CloseOne | null> {
  const saved = parseCloseOne(await read(CLOSE_ONE_KEY));
  if (Platform.OS === "android") {
    const next = closeContactMirror(saved, closeContactPhone());
    if (next !== undefined) mirrorToNative(next);
  }
  return saved;
}

export async function saveCloseOne(contact: CloseOne): Promise<boolean> {
  const ok = await write(CLOSE_ONE_KEY, JSON.stringify({ name: contact.name, number: contact.number }));
  if (!ok) return false;
  // A failed mirror must not leave the native side dialling the previous
  // number while the screen shows the new one: clear it instead.
  if (!mirrorToNative(contact.number)) mirrorToNative(null);
  return true;
}

export async function clearCloseOne(): Promise<boolean> {
  const ok = await write(CLOSE_ONE_KEY, null);
  if (!ok) return false;
  mirrorToNative(null);
  // "Remove number" must remove it everywhere: if the native copy is still
  // there, say the removal failed rather than leave the after-call notice
  // offering it. (An older build has no copy and reads as null.)
  return Platform.OS !== "android" || closeContactPhone() === null;
}
