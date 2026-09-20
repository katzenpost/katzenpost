# mixnet-params

A capacity calculator for the full Echomix component set: gateways,
mix layers, service nodes, couriers, and storage replicas. Given a
target topology, the five operator-tunable emission rates (LambdaP,
LambdaL, LambdaM, LambdaG, LambdaR), the Sphinx
`UserForwardPayloadLength`, and a couple of microbenchmark numbers
from the operator's hardware, it prints:

  - Exact Sphinx packet/header/SURB geometry for a chosen hop count
    and `UserForwardPayloadLength`.
  - Per-mix-node traffic and the Sphinx-unwrap-per-second ceiling.
  - Aggregate courier↔replica drain throughput, including the
    replica↔replica replication mesh (every replica also dials every
    other replica; this is easy to miss and previously wasn't
    counted).
  - Replica MKEM (CTIDH1024-X25519) Decapsulate capacity, and how
    many concurrently-active users that capacity supports for an
    assumed per-user pigeonhole request rate.
  - The precise pigeonhole `MaxPlaintextPayloadLength` that the
    Sphinx geometry leaves room for (after the BACAP, MKEM,
    `CourierEnvelope`, length-prefix wrappers).
  - A predicted pigeonhole-cp wall-clock and bytes/sec for a chosen
    user-payload size, modelling both the BACAP-envelope chunking
    and the copy-stream encoder element layout.
  - Genconfig CLI flags that match the chosen rates.

The pigeonhole and Sphinx geometry math is a verbatim port of
`pigeonhole/geo/geometry.go` and `core/sphinx/geo/geo.go` (formulas
in `mixnet_params/pigeonhole_geo.py` and `mixnet_params/sphinx_geo.py`
respectively). Tests under `tests/` pin the Python output to values
measured on a running docker mixnet and on a real deployment
(namenlos), so the port stays honest if the upstream Go formulas
change.

## Install

From this directory:

```
pip install .
```

Or for development:

```
pip install -e .
```

The console script `mixnet-params` is installed on PATH.

## Use

```
mixnet-params --help
```

A typical sizing pass varies one of `--users`, `--gateways`,
`--nodes-per-layer`, `--services`, `--user-traffic`, `--user-loops`,
`--node-loops`, or `--gateway-loops` and observes whether the
printed per-node load crosses the `max_ops(--benchmark)` ceiling.
`--benchmark` takes a Sphinx-unwrap nanoseconds-per-op number from
a microbenchmark on the operator's hardware; on commodity x86 this
is typically in the ~400 000 ns/op range.

The lambda flags `-P`, `-L`, `-M`, `-G`, `-R` override the
per-component rates with explicit LambdaP / LambdaL / LambdaM /
LambdaG / LambdaR values; the script back-derives the corresponding
traffic and loop rates so the printed output remains internally
consistent.

To size a pigeonhole-cp deployment, set `--user-forward-payload` to
the operator's chosen UFPL and `--cp-payload-bytes` to a
representative cp payload size. The tool prints the BACAP envelope
count, copy-stream chunk count, predicted wall-clock, and predicted
bytes/sec.

For a non-uniform mix topology (e.g. namenlos, whose three layers
have 2/2/3 nodes rather than a uniform count), pass `--layer-sizes
"2,2,3"` instead of `--nodes-per-layer`.

### How many concurrent users can our replicas support?

CTIDH (MKEM Decapsulate) is typically the CPU bottleneck on storage
replicas, not bandwidth. **Operators do not need to run a separate
CTIDH benchmark** — every replica already self-benchmarks MKEM
Decapsulate at startup and logs/caches the result (`OpsPerSecSaturated`)
to `<DataDir>/selfcheck.toml`. Read that one number off any one
replica's file or startup log and pass it as an approximation for the
whole fleet — collecting every replica's file individually is more
trouble than it's worth for what is, either way, a best-effort estimate:

```
mixnet-params --replicas 4 --replica-ops-per-sec 6.08 --user-pigeonhole-rate 0.01
```

`--user-pigeonhole-rate` (pigeonhole requests/sec one concurrently-active
user is assumed to generate) is an *operator assumption*, not a protocol
constant — there is no independent pigeonhole request rate anywhere in
the protocol, so this number has to come from your own traffic-mix
estimate. Without it the tool prints the CTIDH ops/sec budget and the
decaps-per-request range but no concurrent-users figure.

The number of CTIDH decaps one pigeonhole request costs, replica-set-wide,
depends on replica count: with fewer than 4 replicas the courier's 2
intermediate replicas are always the real (fixed, K=2, not tunable) shard
holders, so the cost is exactly 2; with 4 or more replicas the intermediates
exclude the shard holders, so every request is also proxied to them,
typically costing 4 (up to 6 under failover). The tool derives this
automatically from `--replicas`; override with `--decaps-per-request-min/
-typical/-max` if you've measured your own network's actual proxy rate.

If you don't have a `selfcheck.toml`/log handy at all,
`--replica-decap-seconds` remains as a last-resort legacy constant.

## License

AGPL-3.0-only.
