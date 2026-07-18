#!/usr/bin/env bash
# Assert the courier metrics show a fully recovered courier<->replica mesh.
# Intended to run after a chaos cycle has been healed and given a settle
# window. Requires the mixnet to have been started with no_metrics=false so
# the prometheus container is up and scraping.
#
# Usage: chaos_assert_metrics.sh <expected_peer_connected_sum>
#   expected_peer_connected_sum = couriers x replicas (e.g. 2 x 3 = 6)
#
# Exits non-zero (and prints why) if the mesh has not fully recovered:
#   - not every courier<->replica link is connected,
#   - a per-replica send queue is still backed up,
#   - dispatch-semaphore waiters are non-zero (dispatch backpressure).
# Drop counters are printed for visibility but do not fail the check: drops
# during the fault window are expected.
set -u

PROM="${PROM_URL:-http://127.0.0.1:9090}"
EXPECT_PEERS="${1:?usage: chaos_assert_metrics.sh <expected_peer_connected_sum>}"
QUEUE_BOUND="${QUEUE_BOUND:-5}"

q() {
	# Instant PromQL query -> scalar string ("" if no data).
	curl -s -G "$PROM/api/v1/query" --data-urlencode "query=$1" \
		| jq -r '.data.result[0].value[1] // ""'
}

fail=0

peers=$(q 'sum(katzenpost_courier_peer_connected)')
echo "peer_connected sum: ${peers:-<none>} (expected $EXPECT_PEERS)"
if [ -z "$peers" ] || [ "$(printf '%.0f' "$peers")" -ne "$EXPECT_PEERS" ]; then
	echo "FAIL: not every courier<->replica link is connected"
	fail=1
fi

qmax=$(q 'max(katzenpost_courier_queue_length)')
echo "queue_length max: ${qmax:-0} (bound $QUEUE_BOUND)"
if [ -n "$qmax" ] && [ "$(printf '%.0f' "$qmax")" -gt "$QUEUE_BOUND" ]; then
	echo "FAIL: a replica send queue is still backed up"
	fail=1
fi

waiters=$(q 'sum(katzenpost_courier_dispatch_sem_waiters)')
echo "dispatch_sem_waiters sum: ${waiters:-0}"
if [ -n "$waiters" ] && [ "$(printf '%.0f' "$waiters")" -ne 0 ]; then
	echo "FAIL: dispatch semaphore has waiters (dispatch backpressure)"
	fail=1
fi

echo "--- drop counters (informational) ---"
curl -s -G "$PROM/api/v1/query" \
	--data-urlencode 'query=sum by (reason) (katzenpost_courier_dropped_reason_total)' \
	| jq -r '.data.result[]? | "  \(.metric.reason): \(.value[1])"' || true

if [ "$fail" -ne 0 ]; then
	echo "RESULT: courier mesh has NOT fully recovered"
	exit 1
fi
echo "RESULT: courier mesh fully recovered"
