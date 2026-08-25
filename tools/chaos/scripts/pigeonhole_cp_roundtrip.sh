#!/bin/bash
# pigeonhole_cp_roundtrip.sh
#
# Round-trip a random-content file through a pigeonhole channel using
# the Rust `pigeonhole-cp` thin-client tool, then verify the received
# bytes match the original. Exits 0 on success, non-zero on any
# failure (genkey, send, receive, or cmp).
#
# This is a real-workload smoke test for the pigeonhole protocol: the
# COPY command path is exercised by default, BACAP capabilities are
# materialised by `genkey`, and the round-trip touches the courier and
# both K=2 replicas. It is slow by design (the mix network adds tens of
# seconds of delay even for a small file), but it gives an honest
# end-to-end signal that the existing Go integration tests cannot.
#
# Usage:
#   pigeonhole_cp_roundtrip.sh [-s size-bytes] <thinclient.toml> <pigeonhole-cp>
#
# The config and binary are explicit caller-supplied paths; the script has
# no knowledge of any particular network layout. That keeps it usable
# against the docker testnet (the `make pigeonhole-cp-roundtrip` target in
# docker/ supplies the generated config and make-built binary) or any other
# mixnet deployment, real-world included. The default size is 65536 bytes.
set -euo pipefail

usage() {
    cat >&2 <<EOF
Usage: $0 [-s size-bytes] <thinclient.toml> <pigeonhole-cp>

  -s size-bytes      size of the random file to round-trip (default: 65536)
  thinclient.toml    path to the thin-client config for the target mixnet
  pigeonhole-cp      path to the pigeonhole-cp binary (must be executable)
EOF
}

size=65536
while getopts "s:h" opt; do
    case "$opt" in
        s) size="$OPTARG" ;;
        h) usage; exit 0 ;;
        *) usage; exit 2 ;;
    esac
done
shift $((OPTIND - 1))

if [ "$#" -lt 2 ]; then
    echo "pigeonhole_cp_roundtrip: config and binary are required" >&2
    usage
    exit 2
fi
config="$1"
binary="$2"

if [ ! -x "$binary" ]; then
    echo "pigeonhole_cp_roundtrip: $binary is not executable" >&2
    exit 2
fi
if [ ! -f "$config" ]; then
    echo "pigeonhole_cp_roundtrip: $config not found" >&2
    exit 2
fi

workdir=$(mktemp -d -t pigeonhole_cp_roundtrip.XXXXXX)
trap 'rm -rf "$workdir"' EXIT

origin="$workdir/origin.bin"
dest_dir="$workdir/dest"
mkdir -p "$dest_dir"

head -c "$size" /dev/urandom > "$origin"
origin_sha=$(sha256sum "$origin" | awk '{print $1}')
echo "pigeonhole_cp_roundtrip: origin size=$size sha256=$origin_sha"

# Generate the BACAP capability triple. The tool prints three labelled
# values: Read, Write, First Index. We parse each by anchoring on its
# header line.
keyout=$("$binary" genkey --config "$config")
read_cap=$(echo "$keyout"   | awk '/^Read Capability/    {getline; print; exit}')
write_cap=$(echo "$keyout"  | awk '/^Write Capability/   {getline; print; exit}')
first_index=$(echo "$keyout"| awk '/^First Index/        {getline; print; exit}')

if [ -z "$read_cap" ] || [ -z "$write_cap" ] || [ -z "$first_index" ]; then
    echo "pigeonhole_cp_roundtrip: failed to parse genkey output:" >&2
    echo "$keyout" >&2
    exit 1
fi

# Send: the default mode uses the courier Copy command path, which
# gives atomic all-or-nothing semantics on the destination channel.
echo "pigeonhole_cp_roundtrip: send begin"
send_start=$(date +%s)
"$binary" send --config "$config" --write-cap "$write_cap" --index "$first_index" --file "$origin"
send_dur=$(( $(date +%s) - send_start ))
echo "pigeonhole_cp_roundtrip: send done in ${send_dur}s"

# Receive: the tool writes the file into dest_dir using its original
# basename from the embedded FileMetaData header.
echo "pigeonhole_cp_roundtrip: receive begin"
recv_start=$(date +%s)
"$binary" receive --config "$config" --read-cap "$read_cap" --index "$first_index" --dest-dir "$dest_dir"
recv_dur=$(( $(date +%s) - recv_start ))
echo "pigeonhole_cp_roundtrip: receive done in ${recv_dur}s"

received_path=$(find "$dest_dir" -maxdepth 1 -type f | head -1)
if [ -z "$received_path" ]; then
    echo "pigeonhole_cp_roundtrip: FAIL: receive produced no file" >&2
    exit 1
fi

received_size=$(stat -c%s "$received_path")
received_sha=$(sha256sum "$received_path" | awk '{print $1}')
echo "pigeonhole_cp_roundtrip: received size=$received_size sha256=$received_sha"

if [ "$origin_sha" != "$received_sha" ]; then
    echo "pigeonhole_cp_roundtrip: FAIL: sha256 mismatch (origin=$origin_sha received=$received_sha)" >&2
    exit 1
fi
if ! cmp -s "$origin" "$received_path"; then
    echo "pigeonhole_cp_roundtrip: FAIL: cmp says the files differ even though sha256 matched (treat as a bug)" >&2
    exit 1
fi

total=$(( send_dur + recv_dur ))
echo "pigeonhole_cp_roundtrip: PASS ${size}B in ${total}s (${send_dur}s send + ${recv_dur}s recv)"
