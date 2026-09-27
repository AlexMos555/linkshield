/**
 * Part 2 of "Проверка защиты": which family steps apply here, which ones the
 * person marked done, and the "Сделано N из M" line — shared by the checkup
 * screen and its card on the home screen.
 */
import { useCallback, useMemo, useState } from "react";
import { Platform } from "react-native";
import { useFocusEffect } from "expo-router";
import * as Localization from "expo-localization";
import { useTranslation } from "react-i18next";

import { russianStepsVisible } from "../config/market";
import { loadMarks, saveMarks } from "../services/checkup-store";
import {
  familyProgress, familySteps, toggleMark, type FamilyStep, type FamilyStepId,
} from "../utils/checkup";
import { useCloseOne, type CloseOneState } from "./useCloseOne";

export interface FamilySetup {
  steps: FamilyStep[];
  marks: ReadonlySet<FamilyStepId>;
  /** False when the mark could not be stored; the toggle then stays as it was. */
  toggle: (id: FamilyStepId) => Promise<boolean>;
  closeOne: CloseOneState;
  progress: { done: number; total: number };
}

function deviceRegion(): string | null {
  try {
    return Localization.getLocales()[0]?.regionCode ?? null;
  } catch {
    return null;
  }
}

export function useFamilySetup(): FamilySetup {
  const { i18n } = useTranslation();
  const closeOne = useCloseOne();
  const [marks, setMarks] = useState<FamilyStepId[]>([]);

  useFocusEffect(useCallback(() => {
    let alive = true;
    void loadMarks().then((saved) => {
      if (alive) setMarks(saved);
    });
    return () => {
      alive = false;
    };
  }, []));

  const steps = useMemo(
    () => familySteps({
      russia: russianStepsVisible(i18n.language, deviceRegion()),
      android: Platform.OS === "android",
    }),
    [i18n.language],
  );

  const toggle = useCallback(async (id: FamilyStepId) => {
    const next = toggleMark(marks, id);
    setMarks(next);
    const ok = await saveMarks(next);
    // A mark that did not persist would quietly vanish on the next visit —
    // put the screen back to what is really stored.
    if (!ok) setMarks(marks);
    return ok;
  }, [marks]);

  const markSet = useMemo(() => new Set(marks), [marks]);
  const progress = familyProgress(steps, markSet, closeOne.contact !== null);

  return { steps, marks: markSet, toggle, closeOne, progress };
}
