#!/usr/bin/env bash
set -eu
export LC_ALL=C

out=${perf_dir:-perf-compare}
window=${perf_window:-300}
interval=${perf_interval:-10}
writes=${perf_writes:-20}
make=${MAKE:-make}
docker=${docker:-podman}
net=${net_name:-mixnet-alpine}
distro=${distro:-alpine}
read -ra run_args <<< "${docker_args:-}"
params=(wirekem=KYBER768-X25519 mu=0.001 lP=0.001 lL=0.0005 lM=0.0005 lR=0.02 "pkiScheme=Ed25519 Sphincs+"
	no_metrics=false no_decoy=false no_mixdecoy=false)

transport=TCP
trap '[ ! -e "$net/running.stamp" ] || "$make" "${params[@]}" TRANSPORT="$transport" stop' EXIT
mkdir -p "$out"
for transport in TCP QUIC; do
	run=$out/$transport
	rm -rf "$run"
	mkdir -p "$run"
	"$make" "${params[@]}" TRANSPORT=$transport start wait
	project=${net}_$(printf '%s' "$(cat .base_port_seed)" | sha1sum | head -c 5)
	echo "$project" > "$run/project"
	mapfile -t containers < <("$docker" ps --format '{{.Names}}' | grep -E "^${project}[-_]")
	[ ${#containers[@]} -gt 0 ] || { echo "no containers named ${project}-*" >&2; exit 1; }

	end=$(($(date +%s) + window))
	while [ "$(date +%s)" -lt "$end" ]; do
		"$docker" stats --no-stream --format \
			'{{.ContainerStats.Name}} {{.ContainerStats.CPUNano}} {{.ContainerStats.MemUsage}}{{range .ContainerStats.Network}} {{.RxBytes}} {{.TxBytes}}{{end}}' \
			"${containers[@]}" | sed "s/^/$(date +%s) /" >> "$run/stats.txt"
		sleep "$interval"
	done

	"$docker" run --network=host "${run_args[@]}" --rm -w /go/katzenpost/client "katzenpost-${distro}_base" \
		go test -ldflags "${ldflags_body:-}" -tags 'docker_test latency_bench' -run '^$' \
		-bench BenchmarkPigeonholeWrite -benchtime "${writes}x" -count 1 . | tee "$run/latency.txt"

	for cfg in "$net"/*/katzenpost.toml; do
		node=${cfg#"$net"/}
		node=${node%%/*}
		addr=$(sed -n 's/^ *MetricsAddress = "\(.*\)"/\1/p' "$cfg")
		container=$(printf '%s\n' "${containers[@]}" | grep -E "^${project}[-_]${node}([-_][0-9]+)?$" | head -1)
		"$docker" exec "$container" wget -qO- "http://$addr/metrics" |
			grep -E '^katzenpost_(link_handshake_duration_seconds_(sum|count)|links_established_total|link_failures_total|quic_dials_total)' |
			sed "s/^/$node /" >> "$run/metrics.txt"
	done

	"$make" "${params[@]}" TRANSPORT=$transport clean-local
done

summarize() {
	awk -v project="$(cat "$1/project")" '
	function median(a, n,    i, j, t) {
		for (i = 2; i <= n; i++)
			for (j = i; j > 1 && a[j - 1] > a[j]; j--) {
				t = a[j]; a[j] = a[j - 1]; a[j - 1] = t
			}
		return n % 2 ? a[(n + 1) / 2] : (a[n / 2] + a[n / 2 + 1]) / 2
	}
	{
		name = $2
		sub("^" project "[-_]", "", name)
		sub("[-_][0-9]+$", "", name)
		kind = name
		sub("[0-9]+$", "", kind)
		bytes = 0
		for (i = 5; i <= NF; i++)
			bytes += $i
		if (!(name in first)) {
			first[name] = $3
			firstBytes[name] = bytes
			kindOf[name] = kind
		}
		last[name] = $3
		lastBytes[name] = bytes
		mem[name, ++samples[name]] = $4
	}
	END {
		for (name in first) {
			n = samples[name]
			delete m
			for (i = 1; i <= n; i++)
				m[i] = mem[name, i]
			printf "%s %s %.3f %.1f %.3f\n", kindOf[name], name, (last[name] - first[name]) / 1e9, median(m, n) / 1048576, (lastBytes[name] - firstBytes[name]) / 1e6
		}
	}' "$1/stats.txt"
}

kinds() {
	sort | awk '
	function median(a, n,    i, j, t) {
		for (i = 2; i <= n; i++)
			for (j = i; j > 1 && a[j - 1] > a[j]; j--) {
				t = a[j]; a[j] = a[j - 1]; a[j - 1] = t
			}
		return n % 2 ? a[(n + 1) / 2] : (a[n / 2] + a[n / 2 + 1]) / 2
	}
	function flush(    i, lo, hi) {
		if (kind == "")
			return
		lo = cpu[1]; hi = cpu[1]
		for (i = 1; i <= n; i++) {
			if (cpu[i] < lo) lo = cpu[i]
			if (cpu[i] > hi) hi = cpu[i]
		}
		printf "%s %d %.2f %.2f %.2f %.2f %.1f %.2f\n", kind, n, total, median(cpu, n), lo, hi, median(mem, n), bytes
	}
	$1 != kind { flush(); kind = $1; n = 0; total = 0; bytes = 0; delete cpu; delete mem }
	{ cpu[++n] = $3; mem[n] = $4; total += $3; bytes += $5 }
	END { flush() }'
}

metrics() {
	awk '
	function label(s, key,    r) {
		r = s
		if (!match(r, key "=\"[^\"]*\""))
			return ""
		r = substr(r, RSTART + length(key) + 2, RLENGTH - length(key) - 3)
		return r
	}
	{
		v = $NF
		if ($2 ~ /^katzenpost_link_handshake_duration_seconds_sum/) hsum[label($2, "transport") " " label($2, "direction")] += v
		else if ($2 ~ /^katzenpost_link_handshake_duration_seconds_count/) hcount[label($2, "transport") " " label($2, "direction")] += v
		else if ($2 ~ /^katzenpost_links_established_total/) out["links established " label($2, "transport") " " label($2, "direction")] += v
		else if ($2 ~ /^katzenpost_link_failures_total/) out["link failures " label($2, "transport") " " label($2, "direction") " " label($2, "reason")] += v
		else if ($2 ~ /^katzenpost_quic_dials_total/) out["quic dials " label($2, "result")] += v
	}
	END {
		for (k in hcount)
			if (hcount[k] > 0)
				printf "link setup mean ms %s|%.2f\n", k, 1000 * hsum[k] / hcount[k]
		for (k in out)
			printf "%s|%d\n", k, out[k]
	}' "$1/metrics.txt" | sort
}

latency() {
	awk '/median_ms/ { for (i = 2; i <= NF; i++) if ($i == "median_ms" || $i == "p95_ms") printf "pigeonhole write %s|%s\n", $i, $(i - 1) }' "$1/latency.txt"
}

rows() {
	{
		summarize "$out/$1" | kinds | awk '{
			printf "cpu-s %s x%d|%.2f\n", $1, $2, $3
			printf "cpu-s per %s median [min-max]|%.2f [%.2f-%.2f]\n", $1, $4, $5, $6
			printf "mem MiB per %s median|%.1f\n", $1, $7
			printf "net MB %s|%.2f\n", $1, $8
			total += $3
		} END { printf "cpu-s all containers|%.2f\n", total }'
		latency "$out/$1"
		metrics "$out/$1"
	} | sort -t '|' -k 1,1
}

{
	echo "# perf-compare: TCP vs QUIC"
	echo
	echo "window ${window}s sampled every ${interval}s, ${writes} pigeonhole writes, params: ${params[*]}"
	echo
	echo "| measure | TCP | QUIC |"
	echo "|---|---|---|"
	join -t '|' -a 1 -a 2 -e - -o 0,1.2,2.2 <(rows TCP) <(rows QUIC) | sed 's/|/ | /g; s/^/| /; s/$/ |/'
} > "$out/report.md"
cat "$out/report.md"
