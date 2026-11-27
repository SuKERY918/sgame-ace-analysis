#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SDK="${ANDROID_HOME:-/opt/android-sdk}"
BT="$SDK/build-tools/34.0.0"
PLATFORM="$SDK/platforms/android-34/android.jar"

if [ -z "${JAVA_HOME:-}" ]; then
    JAVA_HOME="$(mise where java@17.0.20+101 2>/dev/null || true)"
fi
if [ ! -x "${JAVA_HOME:-}/bin/javac" ]; then
    echo "error: JDK 17 not found (set JAVA_HOME)" >&2
    exit 1
fi
export JAVA_HOME
export PATH="$JAVA_HOME/bin:$PATH"

SRC="$ROOT/app/src/main"
BUILD="$ROOT/build"
DIST="$ROOT/dist"
rm -rf "$BUILD"
mkdir -p "$BUILD/gen" "$BUILD/classes" "$BUILD/dex" "$DIST"

echo "[1/7] aapt2 compile"
"$BT/aapt2" compile --dir "$SRC/res" -o "$BUILD/res.zip"

echo "[2/7] aapt2 link"
"$BT/aapt2" link \
    -o "$BUILD/base.apk" \
    -I "$PLATFORM" \
    --manifest "$SRC/AndroidManifest.xml" \
    --java "$BUILD/gen" \
    --auto-add-overlay \
    "$BUILD/res.zip"

echo "[3/7] javac"
find "$SRC/java" "$BUILD/gen" -name '*.java' > "$BUILD/sources.txt"
"$JAVA_HOME/bin/javac" --release 8 -Xlint:-options \
    -classpath "$PLATFORM" \
    -d "$BUILD/classes" \
    @"$BUILD/sources.txt"

echo "[4/7] d8"
"$JAVA_HOME/bin/jar" cf "$BUILD/classes.jar" -C "$BUILD/classes" .
"$BT/d8" --release --min-api 24 --lib "$PLATFORM" \
    --output "$BUILD/dex" "$BUILD/classes.jar"

echo "[5/7] package"
cp "$BUILD/base.apk" "$BUILD/unsigned.apk"
(cd "$BUILD/dex" && zip -q "$BUILD/unsigned.apk" classes.dex)
"$BT/zipalign" -f 4 "$BUILD/unsigned.apk" "$BUILD/aligned.apk"

echo "[6/7] sign"
KS="${ANDROID_DEBUG_KEYSTORE:-$HOME/.android/debug.keystore}"
mkdir -p "$(dirname "$KS")"
if [ ! -f "$KS" ]; then
    "$JAVA_HOME/bin/keytool" -genkeypair -v \
        -keystore "$KS" \
        -storepass android -keypass android \
        -alias androiddebugkey \
        -dname "CN=Android Debug,O=Android,C=US" \
        -keyalg RSA -keysize 2048 -validity 10000 >/dev/null 2>&1
fi
OUT="$DIST/device-id-viewer-1.0.apk"
"$BT/apksigner" sign \
    --ks "$KS" --ks-pass pass:android --key-pass pass:android \
    --out "$OUT" "$BUILD/aligned.apk"

echo "[7/7] verify"
"$BT/apksigner" verify --verbose --print-certs "$OUT"
ls -lh "$OUT"
