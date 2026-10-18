#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TMP=$(mktemp -d "${TMPDIR:-/tmp}/loopctrl-relay-timeout.XXXXXX")
trap 'rm -rf "$TMP"' EXIT

cp "$ROOT/LoopCtrlKit/RelayRPCClient.swift" "$TMP/"
cp "$ROOT/LoopCtrlKit/SecureEnvelope.swift" "$TMP/"
cp "$ROOT/LoopCtrlKit/ServerPort.swift" "$TMP/"
cp "$ROOT/relay/swift_timeout_check.swift" "$TMP/main.swift"

# Host architecture, plain macOS SDK: this checks the arithmetic and compiles
# the same source that the iOS build compiles.
swiftc \
  "$TMP/RelayRPCClient.swift" \
  "$TMP/SecureEnvelope.swift" \
  "$TMP/ServerPort.swift" \
  "$TMP/main.swift" \
  -o "$TMP/check"

"$TMP/check"
