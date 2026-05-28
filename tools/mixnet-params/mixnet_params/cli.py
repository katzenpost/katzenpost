# SPDX-FileCopyrightText: (c) 2024 Eva Infeld
# SPDX-License-Identifier: AGPL-3.0-only

"""Command-line tool for computing mixnet traffic and capacity parameters.

Models the full Echomix component set: gateways, mix layers, service
nodes, couriers, storage replicas. Tracks all five operator-tunable
emission rates (LambdaP, LambdaL, LambdaM, LambdaG, LambdaR) and the
two cryptographic ceilings that matter in practice: per-mix-node
Sphinx unwrap throughput, and per-replica MKEM (CTIDH1024-X25519)
Decapsulate throughput. Predicts pigeonhole-cp wall-clock and
bytes/sec for a chosen payload size given the Sphinx geometry.

Exposed as the ``mixnet-params`` entry point by the package's
pyproject.toml; see :func:`main` for the click command itself.
"""

import sys

import click

from mixnet_params.pigeonhole_geo import (
    DEFAULT_REPLICA_NIKE_PUBKEY_SIZE,
    copy_stream_element_capacity_bytes,
    copy_stream_elements_required,
    envelope_capacity_bytes,
    envelopes_required,
    max_plaintext_payload_from_ufpl,
)
from mixnet_params.cp_throughput import (
    DEFAULT_PER_CHUNK_SECONDS,
    DEFAULT_PROPAGATION_SECONDS,
    predict_bytes_per_second,
)


@click.command()
# Mix-node capacity benchmark and topology.
@click.option("--benchmark", default=385069, help="Sphinx unwrap nanoseconds/op on the operator's hardware")
@click.option("--average-delay", default=0.2, help="seconds per hop (per-mix-node sphinx delay)")
@click.option("--gateways", default=2)
@click.option("--nodes-per-layer", default=2)
@click.option("--services", default=2)
@click.option("--users", default=2000)
@click.option("--hops", default=11)
# Decoy-rate inputs (one-per-second-style; converted to lambda below).
@click.option("--user-loops", default=0.5, help="rate of decoy loops per second sent by users")
@click.option("--user-traffic", default=1, help="rate of real messages per second sent by user")
@click.option("--node-loops", default=0.5, help="rate of decoy loops per second sent by mix nodes")
@click.option("--gateway-loops", default=1.5, help="rate of decoy loops per second sent by gateways")
# Direct lambda overrides (events per millisecond, the wire-level units).
@click.option("-P", "--LambdaP", "LambdaP", type=float, default=None, help="LambdaP (overrides --user-traffic)")
@click.option("-L", "--LambdaL", "LambdaL", type=float, default=None, help="LambdaL (overrides --user-loops)")
@click.option("-M", "--LambdaM", "LambdaM", type=float, default=None, help="LambdaM (overrides --node-loops)")
@click.option("-G", "--LambdaG", "LambdaG", type=float, default=None, help="LambdaG, per-gateway decoy rate (overrides --gateway-loops)")
@click.option("-R", "--LambdaR", "LambdaR", type=float, default=0.005, help="LambdaR, per-courier-replica connection drain rate")
# Pigeonhole / BACAP / Sphinx geometry.
@click.option("--user-forward-payload", default=2000, help="Sphinx UserForwardPayloadLength")
@click.option("--couriers", default=3, help="number of courier-running service nodes")
@click.option("--replicas", default=5, help="number of storage replicas")
@click.option("--shard-k", default=2, help="K-way fan-out per pigeonhole request (consistent-hashing K)")
@click.option("--replica-nike-pubkey-bytes", default=DEFAULT_REPLICA_NIKE_PUBKEY_SIZE,
              help="bytes of the replica's MKEM sender public key (default 160 for CTIDH1024-X25519)")
@click.option("--replica-decap-seconds", default=0.66,
              help="cost of one MKEM Decapsulate op on the replica (saturated, from the startup self-check)")
# cp-throughput prediction inputs.
@click.option("--cp-payload-bytes", default=65536, help="payload size for the pigeonhole-cp throughput prediction")
@click.option("--cp-per-chunk-seconds", default=DEFAULT_PER_CHUNK_SECONDS,
              help="per-chunk wall-clock cost (calibrated on the docker mixnet; override on slower/faster networks)")
@click.option("--cp-propagation-seconds", default=DEFAULT_PROPAGATION_SECONDS,
              help="propagation wait between temp-stream writes and the Copy command")
def main(
    benchmark,
    average_delay,
    gateways,
    nodes_per_layer,
    services,
    users,
    hops,
    user_loops,
    user_traffic,
    node_loops,
    gateway_loops,
    LambdaP,
    LambdaL,
    LambdaM,
    LambdaG,
    LambdaR,
    user_forward_payload,
    couriers,
    replicas,
    shard_k,
    replica_nike_pubkey_bytes,
    replica_decap_seconds,
    cp_payload_bytes,
    cp_per_chunk_seconds,
    cp_propagation_seconds,
):
    """Compute Katzenpost mixnet capacity parameters."""

    # Lambda flags override their human-readable counterparts. The
    # PKI publishes lambdas in events-per-millisecond, hence the
    # 1e-3 conversion factor.
    if LambdaP is None:
        LambdaP = 1e-3 * user_traffic
    else:
        user_traffic = LambdaP * 1e3

    if LambdaL is None:
        LambdaL = 1e-3 * user_loops
    else:
        user_loops = LambdaL * 1e3

    if LambdaM is None:
        LambdaM = 1e-3 * node_loops
    else:
        node_loops = LambdaM * 1e3

    if LambdaG is None:
        LambdaG = 1e-3 * gateway_loops
    else:
        gateway_loops = LambdaG * 1e3

    # Total node count for the mix-node decoy contribution.
    mix_nodes = nodes_per_layer * 3
    nodes = gateways + services + mix_nodes

    per_node_load = traffic_per_node(
        users=users,
        user_loops=user_loops,
        user_traffic=user_traffic,
        nodes=nodes,
        node_loops=node_loops,
        gateways=gateways,
        gateway_loops=gateway_loops,
        nodes_per_layer=nodes_per_layer,
        services=services,
    )

    # Print the copy-pastable invocation summarising every input.
    print_invocation(locals())

    print()
    print(f"Topology: {gateways} gateways, {mix_nodes} mix nodes ({nodes_per_layer}/layer × 3 layers), {services} service nodes, {couriers} couriers, {replicas} replicas.")
    print()

    # Mix-node ceiling (existing logic).
    mix_ceiling = max_ops(benchmark)
    print("=== Mix-node Sphinx unwrap ===")
    print(f"Average traffic per mix node: {per_node_load:.1f} packets/sec (narrowest layer)")
    print(f"Sphinx unwrap ceiling: {mix_ceiling:.1f} ops/sec (from --benchmark={benchmark} ns/op)")
    if per_node_load > mix_ceiling:
        print(f"WARNING: per-node load {per_node_load:.1f} exceeds Sphinx unwrap ceiling {mix_ceiling:.1f} ops/sec.")
    else:
        headroom = mix_ceiling - per_node_load
        print(f"Headroom: {headroom:.1f} ops/sec.")

    # Courier ceiling. Each of the `couriers * replicas` connections
    # is paced at LambdaR (events per millisecond), so the aggregate
    # courier→replica throughput is the product.
    print()
    print("=== Courier → replica drain ===")
    courier_aggregate_pps = couriers * replicas * LambdaR * 1e3
    print(f"LambdaR: {LambdaR} events/ms ({LambdaR * 1e3:.1f} per-connection events/sec)")
    print(f"Aggregate courier→replica throughput: {courier_aggregate_pps:.1f} ReplicaMessages/sec")
    print(f"  (= {couriers} couriers × {replicas} replicas × {LambdaR * 1e3:.1f} events/sec)")

    # Replica ceiling. Each pigeonhole request lands as `shard_k`
    # ReplicaMessages (the courier's fan-out to K intermediate
    # replicas). Each ReplicaMessage costs one MKEM Decapsulate.
    # System-wide CTIDH op budget is `replicas / replica_decap_seconds`.
    print()
    print("=== Replica MKEM (CTIDH) ===")
    if replica_decap_seconds <= 0:
        print("WARNING: --replica-decap-seconds must be > 0; skipping replica ceiling math.")
        replica_iter_ceiling = float("inf")
    else:
        replica_ops_per_sec_system = replicas / replica_decap_seconds
        replica_iter_ceiling = replica_ops_per_sec_system / shard_k
        print(f"Replica MKEM ops/sec (system-wide, saturated): {replica_ops_per_sec_system:.2f}")
        print(f"  (= {replicas} replicas / {replica_decap_seconds:.3f} s/op)")
        print(f"Pigeonhole iter/sec ceiling: {replica_iter_ceiling:.2f}")
        print(f"  (= replica ops/sec / shard-K of {shard_k})")

    # Pigeonhole + Sphinx geometry. Compute the
    # MaxPlaintextPayloadLength precisely from UFPL, then derive the
    # chunk capacity and predicted cp throughput at the configured
    # payload size.
    print()
    print("=== Pigeonhole/Sphinx geometry ===")
    try:
        box_payload = max_plaintext_payload_from_ufpl(
            user_forward_payload,
            sender_pubkey_size=replica_nike_pubkey_bytes,
        )
        envelope_cap = envelope_capacity_bytes(box_payload)
        element_cap = copy_stream_element_capacity_bytes(box_payload)
    except ValueError as exc:
        print(f"ERROR: {exc}")
        sys.exit(1)
    overhead = user_forward_payload - box_payload
    print(f"UFPL: {user_forward_payload} bytes")
    print(f"Pigeonhole MaxPlaintextPayloadLength: {box_payload} bytes (overhead {overhead})")
    print(f"Per-envelope BACAP plaintext capacity: {envelope_cap} bytes ({box_payload} − 4 length prefix)")
    print(f"Per-element copy-stream capacity: {element_cap} bytes ({box_payload} − 5 stream overhead)")

    # cp-throughput prediction.
    print()
    print("=== Pigeonhole-cp throughput prediction ===")
    chunks = copy_stream_elements_required(
        cp_payload_bytes + 4, box_payload, user_forward_payload
    )
    n_envelopes = envelopes_required(cp_payload_bytes + 4, envelope_cap)
    bps, total_s, _ = predict_bytes_per_second(
        cp_payload_bytes,
        box_payload,
        user_forward_payload,
        per_chunk_seconds=cp_per_chunk_seconds,
        propagation_seconds=cp_propagation_seconds,
    )
    print(f"For a {cp_payload_bytes}-byte payload at UFPL={user_forward_payload}:")
    print(f"  BACAP envelopes: {n_envelopes}")
    print(f"  copy-stream chunks: {chunks}")
    print(f"  predicted wall-clock: {total_s:.1f} s "
          f"(propagation {cp_propagation_seconds:.0f} s + {chunks} × {cp_per_chunk_seconds:.1f} s/chunk)")
    print(f"  predicted throughput: {bps:.1f} bytes/sec")
    if replica_iter_ceiling != float("inf"):
        # System-wide cp throughput ceiling = elements-per-second the
        # replicas can handle, times bytes/element.
        chunks_per_sec_ceiling = replica_iter_ceiling
        sys_bps_ceiling = chunks_per_sec_ceiling * element_cap
        print(f"  system-wide aggregate cp ceiling (saturated): "
              f"{chunks_per_sec_ceiling:.2f} chunks/sec → {sys_bps_ceiling:.0f} B/s "
              f"summed across concurrent transfers")

    # genconfig-friendly footer.
    print()
    print("=== Parameters for genconfig ===")
    print(f"  -lP {LambdaP} -lL {LambdaL} -lM {LambdaM} -lG {LambdaG} -lR {LambdaR}")
    print(f"  --UserForwardPayloadLength {user_forward_payload}")


def print_invocation(params):
    """Emit a copy-pastable command line with every option resolved."""
    args = [
        "benchmark", "average_delay", "gateways", "nodes_per_layer",
        "services", "users", "user_loops", "user_traffic", "node_loops",
        "gateway_loops", "hops", "LambdaP", "LambdaL", "LambdaM",
        "LambdaG", "LambdaR", "user_forward_payload", "couriers",
        "replicas", "shard_k", "replica_nike_pubkey_bytes",
        "replica_decap_seconds", "cp_payload_bytes",
        "cp_per_chunk_seconds", "cp_propagation_seconds",
    ]
    lines = [sys.argv[0] + " \\"]
    for key in args:
        if key not in params:
            continue
        flag = "--" + key.replace("_", "-")
        # click maps -P/--LambdaP to the python identifier "LambdaP"
        # but the CLI flag is "--LambdaP" (camelCase). Match the
        # click registration.
        if key in ("LambdaP", "LambdaL", "LambdaM", "LambdaG", "LambdaR"):
            flag = "--" + key
        lines.append(f"  {flag:>30} {params[key]} \\")
    # Strip the trailing backslash on the last line so the output is
    # actually pasteable.
    lines[-1] = lines[-1].rstrip(" \\")
    print("\n".join(lines))


def max_ops(benchmark):
    """Sphinx unwrap ops/sec from the per-op nanoseconds benchmark."""
    seconds_per_op = 1e-9 * benchmark
    return 1 / seconds_per_op


def traffic_per_layer(
    users,
    user_loops,
    user_traffic,
    mix_nodes,
    node_loops,
    gateways,
    gateway_loops,
):
    """Total packets-per-second offered to the narrowest layer in the
    classic Loopix sense, accounting for:

      - 2× user packets per cycle (each client packet crosses each
        layer once on the forward path and once on the SURB return
        path)
      - mix-node decoy loops (one cross per loop)
      - gateway decoy loops (one cross per loop; this is the
        previously-missing LambdaG contribution)
    """
    per_user = user_traffic + user_loops
    total_user_traffic = 2 * (users * per_user)
    total_node_loops = mix_nodes * node_loops
    total_gateway_loops = gateways * gateway_loops
    return total_user_traffic + total_node_loops + total_gateway_loops


def traffic_per_node(
    users,
    user_loops,
    user_traffic,
    nodes,
    node_loops,
    gateways,
    gateway_loops,
    nodes_per_layer,
    services,
):
    """Per-node load in the narrowest layer."""
    a = min(gateways, nodes_per_layer, services)
    mix_nodes = nodes_per_layer * 3
    total = traffic_per_layer(
        users=users,
        user_loops=user_loops,
        user_traffic=user_traffic,
        mix_nodes=mix_nodes,
        node_loops=node_loops,
        gateways=gateways,
        gateway_loops=gateway_loops,
    )
    return total / a


if __name__ == "__main__":
    main()
