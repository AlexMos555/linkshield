import { useMemo } from "react";
import { StyleSheet, View } from "react-native";

import { encodeQr } from "../../utils/qr";

interface QrCodeProps {
  value: string;
  /** Edge of the whole symbol, quiet zone included (dp). */
  size?: number;
  /** What TalkBack says instead of a picture. */
  label: string;
}

const QUIET_ZONE = 4;

/**
 * The claim code as a QR (src/utils/qr.ts), drawn with plain Views: dark on
 * white, the four-module quiet zone the spec asks for, each row's runs merged
 * into one View so a 29×29 symbol is a few hundred nodes, not nine hundred.
 */
export function QrCode({ value, size = 232, label }: QrCodeProps) {
  const symbol = useMemo(() => {
    try {
      return encodeQr(value);
    } catch {
      return null;
    }
  }, [value]);
  if (!symbol) return null;
  const cells = symbol.size + QUIET_ZONE * 2;
  const cell = Math.max(1, Math.floor(size / cells));
  const edge = cell * cells;
  return (
    <View accessible accessibilityRole="image" accessibilityLabel={label} style={[s.frame, { width: edge, height: edge, padding: cell * QUIET_ZONE }]}>
      {symbol.modules.map((row, r) => (
        <View key={r} style={{ flexDirection: "row", height: cell }}>
          {runs(row).map((run, i) => (
            <View key={i} style={{ width: cell * run.length, height: cell, backgroundColor: run.dark ? "#000000" : "#FFFFFF" }} />
          ))}
        </View>
      ))}
    </View>
  );
}

/** Consecutive modules of one colour, in order. */
function runs(row: readonly boolean[]): Array<{ dark: boolean; length: number }> {
  return row.reduce<Array<{ dark: boolean; length: number }>>((acc, dark) => {
    const last = acc[acc.length - 1];
    if (last && last.dark === dark) return [...acc.slice(0, -1), { dark, length: last.length + 1 }];
    return [...acc, { dark, length: 1 }];
  }, []);
}

const s = StyleSheet.create({
  frame: { backgroundColor: "#FFFFFF", borderRadius: 12, alignSelf: "center", overflow: "hidden" },
});
