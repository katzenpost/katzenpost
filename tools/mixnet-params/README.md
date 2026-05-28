# mixnet-params

A capacity calculator for the full Echomix component set: gateways,
mix layers, service nodes, couriers, and storage replicas. Given a
target topology, the five operator-tunable emission rates (LambdaP,
LambdaL, LambdaM, LambdaG, LambdaR), the Sphinx
`UserForwardPayloadLength`, and a couple of microbenchmark numbers
from the operator's hardware, it prints:

  - Per-mix-node traffic and the Sphinx-unwrap-per-second ceiling.
  - Aggregate courier→replica drain throughput.
  - Replica MKEM (CTIDH1024-X25519) Decapsulate ceiling and the
    pigeonhole iter/sec it implies after the K-way shard fan-out.
  - The precise pigeonhole `MaxPlaintextPayloadLength` that the
    Sphinx geometry leaves room for (after the BACAP, MKEM,
    `CourierEnvelope`, length-prefix wrappers).
  - A predicted pigeonhole-cp wall-clock and bytes/sec for a chosen
    user-payload size, modelling both the BACAP-envelope chunking
    and the copy-stream encoder element layout.
  - Genconfig CLI flags that match the chosen rates.

The pigeonhole and Sphinx geometry math is a verbatim port of
`pigeonhole/geo/geometry.go` and `core/sphinx/geo/geo.go`. Tests
under `tests/` pin the Python output to values measured on a running
docker mixnet and to the `MaxPlaintextPayloadLength` printed in the
generated client config, so the port stays honest if the upstream Go
formulas change.

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
bytes/sec. The replica MKEM Decapsulate cost (`--replica-decap-seconds`)
defaults to the value read off the docker mixnet's startup
self-check; operators on better hardware pass a smaller number.

## License

AGPL-3.0-only.
