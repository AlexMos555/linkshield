/**
 * The saved "Позвонить близкому" contact, re-read whenever a screen that
 * shows it comes into focus — so a number saved on the checkup screen is on
 * the warning screens the next time one opens.
 */
import { useCallback, useState } from "react";
import { useFocusEffect } from "expo-router";

import { clearCloseOne, loadCloseOne, saveCloseOne } from "../services/checkup-store";
import type { CloseOne } from "../utils/checkup";

export interface CloseOneState {
  contact: CloseOne | null;
  /** False until the first read finished — nothing is drawn from a guess. */
  loaded: boolean;
  /** False when it could not be stored; the screen keeps the old value then. */
  save: (contact: CloseOne) => Promise<boolean>;
  remove: () => Promise<boolean>;
}

export function useCloseOne(): CloseOneState {
  const [contact, setContact] = useState<CloseOne | null>(null);
  const [loaded, setLoaded] = useState(false);

  useFocusEffect(useCallback(() => {
    let alive = true;
    void loadCloseOne().then((saved) => {
      if (!alive) return;
      setContact(saved);
      setLoaded(true);
    });
    return () => {
      alive = false;
    };
  }, []));

  const save = useCallback(async (next: CloseOne) => {
    const ok = await saveCloseOne(next);
    if (ok) setContact(next);
    return ok;
  }, []);

  const remove = useCallback(async () => {
    const ok = await clearCloseOne();
    if (ok) setContact(null);
    return ok;
  }, []);

  return { contact, loaded, save, remove };
}
