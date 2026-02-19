#!/bin/bash
# End-to-end test for copycat - run from repo root
set -e

CONFIG="${1:-docker/voting_mixnet/client2/thinclient.toml}"
COPYCAT="./cmd/copycat/copycat"
MSG="test-$RANDOM"

echo "=== Generating keypair ==="
OUTPUT=$($COPYCAT genkey -c "$CONFIG" --thin 2>&1)
READ_CAP=$(echo "$OUTPUT" | grep -A1 "Read Capability" | tail -1 | tr -d ' ')
WRITE_CAP=$(echo "$OUTPUT" | grep -A1 "Write Capability" | tail -1 | tr -d ' ')

echo "=== Sending: $MSG ==="
echo "$MSG" | $COPYCAT send -c "$CONFIG" --thin -w "$WRITE_CAP"

echo "=== Receiving ==="
RECEIVED=$($COPYCAT receive -c "$CONFIG" --thin -r "$READ_CAP" 2>&1 | grep -v "^Reading\|^Done")

echo "=== Result ==="
if [ "$MSG" = "$RECEIVED" ]; then
    echo "SUCCESS: '$RECEIVED'"
else
    echo "FAILURE: expected '$MSG', got '$RECEIVED'"
    exit 1
fi

