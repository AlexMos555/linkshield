#!/bin/bash
# Build the VPN-detection probe APKs with the bare Android SDK (no Gradle).
# Test tool only — never shipped. See README.md for what it measures.
#
#   probe.apk         ai.cleanway.probe          targetSdk 34, launcher icon
#   probe-legacy.apk  ai.cleanway.probe.legacy   targetSdk 28, launcher icon (older SELinux domain,
#                                                no package-visibility limits)
#   probe-hidden.apk  ai.cleanway.probe.hidden   targetSdk 34, NO launcher icon (invisible to
#                                                Cleanway's launcher <queries>)
#   stub-max.apk      ru.oneme.app               EMULATOR-ONLY stand-in carrying a listed package
#   stub-ozon.apk     ru.ozon.app.android        name, to exercise the default list / suggestions
#
# Env: ANDROID_HOME (default: Homebrew commandlinetools), JAVA_HOME (JDK 17).
# Output goes to out/ and *.apk here; the throwaway signing key to keystore.jks
# (all git-ignored).
set -euo pipefail
cd "$(dirname "$0")"
export JAVA_HOME=${JAVA_HOME:-/opt/homebrew/opt/openjdk@17}
export PATH="$JAVA_HOME/bin:$PATH"
SDK=${ANDROID_HOME:-/opt/homebrew/share/android-commandlinetools}
BT=$SDK/build-tools/35.0.0
JAR=$SDK/platforms/android-35/android.jar
rm -rf out && mkdir -p out/classes out/dex
javac --release 11 -classpath "$JAR" -d out/classes src/ai/cleanway/probe/MainActivity.java 2>&1 | grep -v "^Note:" || true
"$BT/d8" --release --min-api 24 --lib "$JAR" --output out/dex $(find out/classes -name '*.class')
[ -f keystore.jks ] || keytool -genkeypair -keystore keystore.jks -storepass probeprobe -keypass probeprobe \
  -alias probe -keyalg RSA -keysize 2048 -validity 3650 -dname "CN=Cleanway VPN probe (test only)" >/dev/null 2>&1

build() { # name package targetSdk launcher(yes/no) label
  local name=$1 pkg=$2 target=$3 launcher=$4 label=$5
  local filter=""
  if [ "$launcher" = yes ]; then
    filter='<intent-filter><action android:name="android.intent.action.MAIN"/><category android:name="android.intent.category.LAUNCHER"/></intent-filter>'
  fi
  cat > out/AndroidManifest-$name.xml <<EOF
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="$pkg">
  <uses-permission android:name="android.permission.INTERNET"/>
  <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE"/>
  <queries><intent><action android:name="android.net.VpnService"/></intent></queries>
  <application android:label="$label" android:debuggable="true" android:usesCleartextTraffic="true">
    <activity android:name="ai.cleanway.probe.MainActivity" android:exported="true" android:launchMode="singleTop">
      $filter
    </activity>
  </application>
</manifest>
EOF
  "$BT/aapt2" link -o out/$name-unsigned.apk --manifest out/AndroidManifest-$name.xml -I "$JAR" \
    --min-sdk-version 24 --target-sdk-version "$target" --version-code 1 --version-name 1.0
  (cd out/dex && zip -q ../$name-unsigned.apk classes.dex)
  "$BT/zipalign" -f 4 out/$name-unsigned.apk out/$name-aligned.apk
  "$BT/apksigner" sign --ks keystore.jks --ks-pass pass:probeprobe --out $name.apk out/$name-aligned.apk
  echo "built $name.apk ($pkg, targetSdk $target, launcher=$launcher)"
}
build probe ai.cleanway.probe 34 yes "VPN probe"
build probe-legacy ai.cleanway.probe.legacy 28 yes "VPN probe (t28)"
build probe-hidden ai.cleanway.probe.hidden 34 no "VPN probe (hidden)"
build stub-max ru.oneme.app 34 yes "MAX (test stub)"
build stub-ozon ru.ozon.app.android 34 yes "Ozon (test stub)"
