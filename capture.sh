#!/usr/bin/env bash
# capture.sh — collect Android telephony state for carrier-diff.
#
# Run this TWICE: once while the Owner profile is active, once while the
# affected secondary user is active. Switch users on-device between runs.
#
# Usage:
#   ./capture.sh owner
#   (switch to secondary user on the device)
#   ./capture.sh secondary
#
# Output: <label>.txt in the current directory, sectioned for carrier_diff.py.
#
# Requires: adb with the device authorized. On GrapheneOS, ADB debugging
# must be enabled in the active profile's Developer options.

set -euo pipefail

LABEL="${1:?usage: ./capture.sh <label>   e.g. ./capture.sh owner}"
if ! [[ "$LABEL" =~ ^[A-Za-z0-9_-]{1,32}$ ]]; then
    echo "error: label must be 1-32 chars of [A-Za-z0-9_-] (path traversal guard)" >&2
    exit 1
fi
OUT="${LABEL}.txt"

# Captures contain device and subscriber identifiers: owner-only perms.
umask 077

if ! command -v adb >/dev/null 2>&1; then
    echo "error: adb not found in PATH" >&2
    exit 1
fi
if ! adb get-state >/dev/null 2>&1; then
    echo "error: no authorized device (check USB debugging + authorization prompt)" >&2
    exit 1
fi

section() {
    echo "### SECTION: $1 ###" >> "$OUT"
}

# Run an adb command with a fallback marker instead of aborting the capture.
grab() {
    local key="$1"; shift
    "$@" >> "$OUT" 2>/dev/null || echo "${key}=UNAVAILABLE" >> "$OUT"
}

# Remove any pre-existing file/symlink so the capture is always a fresh
# file created under umask 077 (symlink-truncation guard).
rm -f -- "$OUT"
: > "$OUT"

echo "capturing telephony state -> $OUT"

section meta
echo "capture_label=$LABEL" >> "$OUT"
echo "capture_time=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$OUT"
echo "current_user=$(adb shell am get-current-user 2>/dev/null | tr -d '\r' || echo UNKNOWN)" >> "$OUT"
echo "build=$(adb shell getprop ro.build.fingerprint 2>/dev/null | tr -d '\r' || echo UNKNOWN)" >> "$OUT"

section carrier_config
grab carrier_config_dump adb shell dumpsys carrier_config

section telephony_registry
grab telephony_registry_dump adb shell dumpsys telephony.registry

section subscription
grab isub_dump adb shell dumpsys isub

section user_restrictions
grab user_dump adb shell dumpsys user

echo "done: $OUT ($(wc -l < "$OUT") lines)"
echo "next: switch profiles on-device and run ./capture.sh <other_label>"
