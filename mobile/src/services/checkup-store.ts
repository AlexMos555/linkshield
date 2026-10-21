/**
 * What the "Проверка защиты" screen remembers — on this phone only.
 *
 * Two things, both in expo-secure-store (encrypted with a key in the
 * phone's keystore, and — unlike SharedPreferences — left out of Android's
 * cloud backup, see docs/PRIVACY.md):
 *  - the family steps the person marked "done";
 *  - the saved "Позвонить близкому" contact: a name and a number.
 *
 * Nothing here is sent anywhere, synced to an account or logged. Reads are
 * re-validated (utils/checkup.ts): storage is not trusted to hold what we
 * wrote, and a broken value reads as "nothing saved", never as a crash.
 */
import * as SecureStore from "expo-secure-store";

import {
  parseCloseOne, parseMarks, type CloseOne, type FamilyStepId,
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

export async function loadMarks(): Promise<FamilyStepId[]> {
  return parseMarks(await read(MARKS_KEY));
}

export function saveMarks(marks: readonly FamilyStepId[]): Promise<boolean> {
  return write(MARKS_KEY, JSON.stringify(marks));
}

export async function loadCloseOne(): Promise<CloseOne | null> {
  return parseCloseOne(await read(CLOSE_ONE_KEY));
}

export function saveCloseOne(contact: CloseOne): Promise<boolean> {
  return write(CLOSE_ONE_KEY, JSON.stringify({ name: contact.name, number: contact.number }));
}

export function clearCloseOne(): Promise<boolean> {
  return write(CLOSE_ONE_KEY, null);
}
