#!/bin/bash
# Run the probe inside one or more installed probe packages and print each summary.
#
#   ADB_SERIAL=emulator-5554 ./run.sh <label> [package ...]
#
# Default packages: the three probes. The full report of each run lands in
# raw/<label>--<package>.txt (also in logcat, tag CwProbe). ADB_SERIAL is
# required on purpose: never point this at a phone you did not mean to.
set -u
cd "$(dirname "$0")"
: "${ADB_SERIAL:?set ADB_SERIAL (adb devices) — e.g. emulator-5554}"
ADB="${ANDROID_HOME:-/opt/homebrew/share/android-commandlinetools}/platform-tools/adb -s $ADB_SERIAL"
LABEL=$1; shift
PKGS=("$@")
[ ${#PKGS[@]} -eq 0 ] && PKGS=(ai.cleanway.probe ai.cleanway.probe.legacy ai.cleanway.probe.hidden)
mkdir -p raw
for pkg in "${PKGS[@]}"; do
  $ADB shell am force-stop "$pkg"
  $ADB shell rm -f "/sdcard/Android/data/$pkg/files/probe-$LABEL.txt"
  $ADB shell am start -W -n "$pkg/ai.cleanway.probe.MainActivity" --ez auto true --es label "$LABEL" >/dev/null
  for _ in $(seq 1 60); do
    $ADB shell ls "/sdcard/Android/data/$pkg/files/probe-$LABEL.txt" >/dev/null 2>&1 && break
    sleep 1
  done
  if $ADB pull "/sdcard/Android/data/$pkg/files/probe-$LABEL.txt" "raw/$LABEL--$pkg.txt" >/dev/null 2>&1; then
    echo "== $pkg"; sed -n '/--- SUMMARY/,$p' "raw/$LABEL--$pkg.txt"
  else
    echo "== $pkg: NO REPORT"
  fi
done
# Which UIDs the VPN covers right now (an excluded app's UID is missing from the range).
echo "== VPN UID ranges"
$ADB shell dumpsys connectivity | grep -o 'Transports: [A-Z|]*VPN[^]]*' | grep -o 'Uids: <[^>]*>' | sort -u
