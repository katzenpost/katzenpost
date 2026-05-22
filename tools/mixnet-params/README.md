# mixnet-params

A capacity calculator for Katzenpost mixnet operator-tunable
parameters. Given a target topology shape and traffic profile, it
prints the steady-state traffic each mix node must handle, the
genconfig CLI flags that match the chosen rates, and a warning when
the configuration exceeds the Sphinx-unwrap-per-second ceiling implied
by the supplied microbenchmark.

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
or `--node-loops` and observes whether the printed per-node load
crosses the `max_ops(--benchmark)` ceiling. The `--benchmark` flag
takes a Sphinx-unwrap nanoseconds-per-op number from a microbenchmark
on the operator's hardware; on commodity x86 this is typically in the
~400 000 ns/op range.

The lambda flags `-P`, `-L`, `-M` override the per-user-and-per-node
rates with explicit LambdaP / LambdaL / LambdaM values; the script
back-derives the corresponding traffic and loop rates so the printed
output remains internally consistent.

## License

AGPL-3.0-only.
