/**
 * The two things the checkup screen hands to the rest of the phone: an
 * official page, and a call to the saved close one.
 */
import { Linking } from "react-native";

import { dialNumber, isDefaultLinkHandler, openInBrowser } from "../../modules/cleanway-vpn";
import { normalizePhone } from "../utils/phone-number";

/**
 * Open an official page from config/official-links.ts.
 *
 * While Cleanway holds the browser role, a plain openURL comes straight
 * back to our own link guard, which would forward it AND send the host for
 * a background check — so this goes to a real browser directly and nothing
 * leaves the phone. Otherwise the phone decides (the Госуслуги app, if it
 * claims its links). False when nothing could open it.
 */
export async function openOfficialPage(url: string): Promise<boolean> {
  if (isDefaultLinkHandler() && openInBrowser(url)) return true;
  try {
    await Linking.openURL(url);
    return true;
  } catch {
    return false;
  }
}

/**
 * Open the dialer with the close one's number filled in. The person still
 * presses call; the app never dials by itself and holds no call permission.
 * Native ACTION_DIAL first; a tel: link where that is missing (iOS, an older
 * build), which on Android opens the same dialer.
 */
export async function callCloseOne(number: string): Promise<boolean> {
  const dialable = normalizePhone(number);
  if (!dialable) return false;
  if (dialNumber(dialable)) return true;
  try {
    await Linking.openURL(`tel:${dialable}`);
    return true;
  } catch {
    return false;
  }
}
