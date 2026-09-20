# SPDX-FileCopyrightText: (c) 2024 Eva Infeld
# SPDX-License-Identifier: AGPL-3.0-only

"""Command-line tool for computing mixnet traffic and capacity parameters.

Models the full Echomix component set: gateways, mix layers, service
nodes, couriers, storage replicas. Tracks all five operator-tunable
emission rates (LambdaP, LambdaL, LambdaM, LambdaG, LambdaR) and the
two cryptographic ceilings that matter in practice: per-mix-node
Sphinx unwrap throughput, and per-replica MKEM (CTIDH1024-X25519)
Decapsulate throughput -- including how many concurrently-active
users that CTIDH throughput can support. Predicts pigeonhole-cp
wall-clock and bytes/sec for a chosen payload size given the Sphinx
geometry.

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
from mixnet_params.sphinx_geo import (
    derive_forward_payload_length,
    header_length,
    packet_length,
    per_hop_routing_info_length,
    routing_info_length,
    surb_length,
)
from mixnet_params.replica_capacity import (
    concurrent_users_ceiling,
    default_decaps_per_request,
    replica_inbound_connections,
    replica_mesh_pps,
)


@click.command()
# Mix-node capacity benchmark and topology.
@click.option("--benchmark", default=385069, help="Sphinx unwrap nanoseconds/op on the operator's hardware")
@click.option("--average-delay", default=0.2, help="seconds per hop (per-mix-node sphinx delay)")
@click.option("--gateways", default=2)
@click.option("--nodes-per-layer", default=2, help="uniform per-layer mix node count; overridden by --layer-sizes")
@click.option("--layer-sizes", default=None, type=str,
              help='comma-separated per-layer mix-node counts, e.g. "2,2,3" (see namenlos '
                   'SSOT/topology.toml), for a non-uniform topology; overrides --nodes-per-layer')
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
@click.option("-R", "--LambdaR", "LambdaR", type=float, default=0.00025,
              help="LambdaR, per-courier/replica-connection decoy rate. Defaults to the katzenpost "
                   "code default (authority/voting/server/config/config.go); pass your deployment's "
                   "real value, e.g. -R 0.02 for namenlos (SSOT/topology.toml [Parameters]).")
# Pigeonhole / BACAP / Sphinx geometry.
@click.option("--user-forward-payload", default=2000, help="Sphinx UserForwardPayloadLength")
@click.option("--sphinx-nike-pubkey-bytes", default=32, help="Sphinx transport NIKE public-key size (default 32, x25519)")
@click.option("--with-surb/--no-with-surb", "with_surb", default=True, help="whether the forward payload carries a SURB")
@click.option("--couriers", default=3, help="number of courier-running service nodes")
@click.option("--replicas", default=5, help="number of storage replicas")
@click.option("--replica-nike-pubkey-bytes", default=DEFAULT_REPLICA_NIKE_PUBKEY_SIZE,
              help="bytes of the replica's MKEM sender public key (default 160 for CTIDH1024-X25519)")
# Replica CTIDH capacity: an approximate per-replica ops/sec number, in
# priority order over the legacy seconds-per-op constant.
@click.option("--replica-ops-per-sec", type=float, default=None,
              help="approximate CTIDH ops/sec for ONE replica (saturated). Every replica already "
                   "measures this at startup and logs/caches it to <DataDir>/selfcheck.toml -- "
                   "read OpsPerSecSaturated off one replica's file or startup log and pass it "
                   "here; total budget = this x --replicas.")
@click.option("--replica-decap-seconds", default=0.66,
              help="legacy fallback: assumed cost of one MKEM Decapsulate op per replica, only "
                   "used when --replica-ops-per-sec is not given")
@click.option("--decaps-per-request-min", type=float, default=None,
              help="override the minimum CTIDH decaps one pigeonhole request costs replica-set-wide "
                   "(default derived from --replicas; see --help output's capacity section)")
@click.option("--decaps-per-request-typical", type=float, default=None,
              help="override the typical CTIDH decaps one pigeonhole request costs replica-set-wide")
@click.option("--decaps-per-request-max", type=float, default=None,
              help="override the worst-case CTIDH decaps one pigeonhole request costs replica-set-wide")
@click.option("--user-pigeonhole-rate", type=float, default=None,
              help="ASSUMPTION, not a protocol constant: pigeonhole (BACAP) requests/sec issued by "
                   "one concurrently-active user. Pigeonhole requests share the ordinary LambdaP-paced "
                   "send queue -- there is no independent per-user pigeonhole rate anywhere in the "
                   "protocol, so this must come from the operator's own traffic-mix estimate.")
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
    layer_sizes,
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
    sphinx_nike_pubkey_bytes,
    with_surb,
    couriers,
    replicas,
    replica_nike_pubkey_bytes,
    replica_ops_per_sec,
    replica_decap_seconds,
    decaps_per_request_min,
    decaps_per_request_typical,
    decaps_per_request_max,
    user_pigeonhole_rate,
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

    # Topology: either a uniform per-layer count, or the real per-layer
    # sizes for a non-uniform deployment (e.g. namenlos's 2/2/3 layers).
    if layer_sizes:
        layer_size_list = [int(x.strip()) for x in layer_sizes.split(",")]
        mix_nodes = sum(layer_size_list)
        narrowest_layer = min(layer_size_list)
    else:
        layer_size_list = None
        mix_nodes = nodes_per_layer * 3
        narrowest_layer = nodes_per_layer

    per_node_load = traffic_per_node(
        users=users,
        user_loops=user_loops,
        user_traffic=user_traffic,
        node_loops=node_loops,
        gateways=gateways,
        gateway_loops=gateway_loops,
        narrowest_layer=narrowest_layer,
        services=services,
        mix_nodes=mix_nodes,
    )

    # Print the copy-pastable invocation summarising every input.
    print_invocation(locals())

    print()
    if layer_size_list:
        layer_desc = f"{mix_nodes} mix nodes (layers: {'/'.join(map(str, layer_size_list))})"
    else:
        layer_desc = f"{mix_nodes} mix nodes ({nodes_per_layer}/layer × 3 layers)"
    print(f"Topology: {gateways} gateways, {layer_desc}, {services} service nodes, {couriers} couriers, {replicas} replicas.")

    # Sphinx packet geometry (NIKE Sphinx only for now -- namenlos and the
    # docker mixnet both run NIKE Sphinx; the KEM variant is available in
    # sphinx_geo.per_hop_routing_info_length but not wired in here yet).
    print()
    print("=== Sphinx packet geometry ===")
    one_hop = per_hop_routing_info_length()
    routing_info = routing_info_length(hops, one_hop)
    sphinx_hdr = header_length(sphinx_nike_pubkey_bytes, routing_info)
    sphinx_surb = surb_length(sphinx_hdr)
    if with_surb:
        sphinx_fwd = derive_forward_payload_length(user_forward_payload, sphinx_surb)
    else:
        sphinx_fwd = user_forward_payload
    sphinx_pkt = packet_length(sphinx_hdr, sphinx_fwd)
    print(f"NrHops: {hops}")
    print(f"PerHopRoutingInfoLength: {one_hop} bytes")
    print(f"RoutingInfoLength: {routing_info} bytes")
    print(f"HeaderLength: {sphinx_hdr} bytes")
    print(f"SURBLength: {sphinx_surb} bytes")
    print(f"UserForwardPayloadLength: {user_forward_payload} bytes "
          f"(the application-usable payload -- what a client actually gets to fill with data)")
    print(f"ForwardPayloadLength: {sphinx_fwd} bytes (with-SURB={with_surb})")
    print(f"PacketLength: {sphinx_pkt} bytes")

    # Mix-node ceiling (existing logic).
    print()
    mix_ceiling = max_ops(benchmark)
    print("=== Mix-node Sphinx unwrap ===")
    print(f"Average traffic per mix node: {per_node_load:.1f} packets/sec (narrowest layer)")
    print(f"Sphinx unwrap ceiling: {mix_ceiling:.1f} ops/sec (from --benchmark={benchmark} ns/op)")
    if per_node_load > mix_ceiling:
        print(f"WARNING: per-node load {per_node_load:.1f} exceeds Sphinx unwrap ceiling {mix_ceiling:.1f} ops/sec.")
    else:
        headroom = mix_ceiling - per_node_load
        print(f"Headroom: {headroom:.1f} ops/sec.")

    # Courier <-> replica mesh. Every courier maintains a LambdaR-paced
    # connection to every replica, AND every replica maintains one to
    # every OTHER replica ("Connect to all replicas for replication
    # purposes", replica/connector.go); both use the same paced sender
    # (replica/sender.go). Decoy traffic on these links is free CTIDH-wise
    # (replica/handlers.go) -- this section is connection/bandwidth budget
    # only, not a CTIDH constraint.
    print()
    print("=== Courier ↔ replica drain ===")
    courier_aggregate_pps = couriers * replicas * LambdaR * 1e3
    mesh_pps = replica_mesh_pps(replicas, LambdaR)
    total_pps = courier_aggregate_pps + mesh_pps
    print(f"LambdaR: {LambdaR} events/ms ({LambdaR * 1e3:.1f} per-connection events/sec)")
    print(f"Courier→replica throughput: {courier_aggregate_pps:.1f} ReplicaMessages/sec")
    print(f"  (= {couriers} couriers × {replicas} replicas × {LambdaR * 1e3:.1f} events/sec)")
    print(f"Replica↔replica mesh throughput: {mesh_pps:.1f} ReplicaMessages/sec")
    print(f"  (= {replicas} replicas × {replicas - 1} peer(s) × {LambdaR * 1e3:.1f} events/sec)")
    print(f"Total aggregate drain (courier mesh + replica mesh): {total_pps:.1f} ReplicaMessages/sec")
    print(f"Per-replica inbound connections: {replica_inbound_connections(couriers, replicas)} "
          f"(= {couriers} couriers + {replicas - 1} other replica(s))")
    print("  Note: decoy traffic on these links costs zero CTIDH; this is a connection/bandwidth "
          "budget only, separate from the CTIDH capacity section below.")

    # Replica CTIDH capacity. Real replicas self-benchmark MKEM Decapsulate
    # at startup and cache the result (replica/selfcheck.go,
    # core/selfcheckcache/cache.go); operators read the approximate
    # OpsPerSecSaturated number off one replica's file or log themselves and
    # pass it via --replica-ops-per-sec, rather than the tool collecting
    # every replica's file (more trouble than it's worth for what is, either
    # way, a best-effort estimate).
    print()
    print("=== Replica MKEM (CTIDH) capacity ===")
    if replica_ops_per_sec is not None:
        system_ops_per_sec = replicas * replica_ops_per_sec
        budget_source = f"--replica-ops-per-sec={replica_ops_per_sec} × {replicas} replicas"
    elif replica_decap_seconds > 0:
        system_ops_per_sec = replicas / replica_decap_seconds
        budget_source = f"legacy --replica-decap-seconds={replica_decap_seconds}"
    else:
        print("WARNING: --replica-decap-seconds must be > 0; skipping replica ceiling math.")
        system_ops_per_sec = 0.0
        budget_source = "none (invalid --replica-decap-seconds)"

    print(f"CTIDH budget source: {budget_source} (ASSUMES all replicas are equally capable)")
    print(f"System-wide CTIDH ops/sec (saturated; decoy traffic is free): {system_ops_per_sec:.2f}")

    default_min, default_typical, default_max = default_decaps_per_request(replicas)
    d_min = decaps_per_request_min if decaps_per_request_min is not None else default_min
    d_typical = decaps_per_request_typical if decaps_per_request_typical is not None else default_typical
    d_max = decaps_per_request_max if decaps_per_request_max is not None else default_max

    print()
    print(f"Decaps per pigeonhole request (replica-set-wide): min={d_min:g} typical={d_typical:g} max={d_max:g}")
    if replicas < 4:
        print(f"  ({replicas} replicas < 4: the 2 intermediate replicas ARE the K=2 shard holders, "
              f"no proxy hop -- pigeonhole/pki.go)")
    else:
        print(f"  ({replicas} replicas >= 4: intermediates exclude the K=2 shard holders, so every "
              f"request is also proxied to them -- pigeonhole/pki.go)")

    if system_ops_per_sec > 0:
        iter_ceiling_best = system_ops_per_sec / d_min
        iter_ceiling_typical = system_ops_per_sec / d_typical
        iter_ceiling_worst = system_ops_per_sec / d_max
    else:
        iter_ceiling_best = iter_ceiling_typical = iter_ceiling_worst = 0.0

    print()
    print(f"Pigeonhole request/sec ceiling (system-wide, saturated): "
          f"{iter_ceiling_typical:.2f} typical / {iter_ceiling_worst:.2f} worst-case")

    print()
    if user_pigeonhole_rate:
        users_best = concurrent_users_ceiling(system_ops_per_sec, d_min, user_pigeonhole_rate)
        users_typical = concurrent_users_ceiling(system_ops_per_sec, d_typical, user_pigeonhole_rate)
        users_worst = concurrent_users_ceiling(system_ops_per_sec, d_max, user_pigeonhole_rate)
        print(f"Concurrent users supported (CTIDH-bound) at "
              f"--user-pigeonhole-rate={user_pigeonhole_rate:g} req/sec/user:")
        print(f"  best case  (min decaps/req): {users_best:.0f} users")
        print(f"  typical    (typical decaps/req): {users_typical:.0f} users")
        print(f"  worst case (max decaps/req): {users_worst:.0f} users")
    else:
        print("Pass --user-pigeonhole-rate <req/sec/user> (an operator assumption, not a protocol "
              "constant -- see README) to get a concurrent-users estimate.")

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
    if iter_ceiling_typical > 0:
        # System-wide cp throughput ceiling = elements-per-second the
        # replicas can handle (typical case), times bytes/element.
        sys_bps_ceiling = iter_ceiling_typical * element_cap
        print(f"  system-wide aggregate cp ceiling (saturated, typical case): "
              f"{iter_ceiling_typical:.2f} chunks/sec → {sys_bps_ceiling:.0f} B/s "
              f"summed across concurrent transfers")

    # genconfig-friendly footer.
    print()
    print("=== Parameters for genconfig ===")
    print(f"  -lP {LambdaP} -lL {LambdaL} -lM {LambdaM} -lG {LambdaG} -lR {LambdaR}")
    print(f"  --UserForwardPayloadLength {user_forward_payload}")


def print_invocation(params):
    """Emit a copy-pastable command line with every option resolved."""
    args = [
        "benchmark", "average_delay", "gateways", "nodes_per_layer", "layer_sizes",
        "services", "users", "user_loops", "user_traffic", "node_loops",
        "gateway_loops", "hops", "LambdaP", "LambdaL", "LambdaM",
        "LambdaG", "LambdaR", "user_forward_payload", "sphinx_nike_pubkey_bytes",
        "with_surb", "couriers", "replicas", "replica_nike_pubkey_bytes",
        "replica_ops_per_sec", "replica_decap_seconds",
        "decaps_per_request_min", "decaps_per_request_typical", "decaps_per_request_max",
        "user_pigeonhole_rate", "cp_payload_bytes",
        "cp_per_chunk_seconds", "cp_propagation_seconds",
    ]
    lines = [sys.argv[0] + " \\"]
    for key in args:
        if key not in params or params[key] is None:
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
    node_loops,
    gateways,
    gateway_loops,
    narrowest_layer,
    services,
    mix_nodes=None,
):
    """Per-node load in the narrowest layer. ``narrowest_layer`` is the
    node count of whichever layer (gateways, a mix layer, or services) is
    smallest; ``mix_nodes`` is the total mix-node count across all layers
    (defaults to ``narrowest_layer * 3`` for the classic uniform-3-layer
    topology, but callers with a non-uniform topology -- e.g. --layer-sizes
    -- should pass the real total)."""
    a = min(gateways, narrowest_layer, services)
    if mix_nodes is None:
        mix_nodes = narrowest_layer * 3
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
