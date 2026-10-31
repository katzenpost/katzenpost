#!/bin/sh
# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
#
# Entry point of the Reticulum bridge test container: a mesh replica bridged
# to the Katzenpost replica whose DataDir holds bridge.sock, and the bot that
# answers the client docker test's jobs. Both share one RNS instance.
#
#   docker_entry.sh /mixnet-alpine 1
set -eu
net="$1"
bridge_replica="$2"
dir="$net/reticulum"
mkdir -p "$dir/rns" "$dir/jobs" "$dir/store"
cat > "$dir/rns/config" <<EOF
[reticulum]
  enable_transport = No
  share_instance = Yes
[logging]
  loglevel = 4
EOF
cd /go/katzenpost/reticulum
python -m pigeonhole_rns.cli --config "$dir/rns" --box-size 0 -v replica \
  --storage "$dir/store" --announce-interval 5 \
  --bridge-socket "$net/replica$bridge_replica/bridge.sock" > "$dir/replica.log" 2>&1 &
sleep 3
exec python tests/docker_bot.py --config "$dir/rns" --jobs "$dir/jobs"
