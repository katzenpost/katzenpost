#!/bin/sh
# Fetch the namenlos client config to $1. kno holds the only copy.
set -eu

url=https://raw.githubusercontent.com/katzenpost/kno/main/data/networks/namenlos/.generated/configs/client.toml
curl -fsSL --retry 3 -o "$1" "$url"
# thinclient.toml dials @katzenpost, so the daemon has to listen there.
grep -q '"@katzenpost"' "$1" \
    || { printf '%s\n' "$url does not listen on @katzenpost" >&2; exit 1; }
