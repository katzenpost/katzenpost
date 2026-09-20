# SPDX-FileCopyrightText: (c) 2024 Eva Infeld
# SPDX-License-Identifier: AGPL-3.0-only

"""Storage-replica CTIDH capacity arithmetic.

Pure functions modelling the actual CPU bottleneck on Katzenpost's pigeonhole
storage replicas: CTIDH1024-X25519 MKEM Decapsulate operations. Every number
here is derived from, and cited against, the real replica implementation
(``replica/*.go`` in the katzenpost monorepo) rather than the informal
description in the Echomix paper, which does not model this cost at all.

Key facts this module encodes (see each function's docstring for the exact
file:line citation):

- Decoy traffic between couriers and replicas costs zero CTIDH ops --
  ``replica/handlers.go``'s ``ReplicaDecoy`` handler never touches MKEM. Only
  a real client request (wrapped in a CourierEnvelope) reaches Decapsulate.
- The number of Decapsulate operations one client pigeonhole request costs,
  replica-set-wide, is NOT the fixed K=2 of the hash-based sharding scheme:
  once a deployment has 4 or more replicas, the courier's 2 intermediate
  replicas are chosen to exclude the real K=2 shard holders, so every
  request also gets proxied to the shard holders -- roughly doubling the
  real cost.
- There is no protocol-level "requests per second per user" for pigeonhole
  traffic; it must be an operator-supplied assumption.
"""

try:
    import tomllib
except ModuleNotFoundError:  # Python < 3.11
    import tomli as tomllib


def parse_selfcheck_toml(raw: bytes) -> dict:
    """Parse the contents of one replica's self-check cache file.

    Every real replica measures its own CTIDH (MKEM Decapsulate) throughput
    at startup and persists the result to ``<DataDir>/selfcheck.toml``
    (``replica/selfcheck_cache.go``), using the untagged struct defined in
    ``core/selfcheckcache/cache.go:48-55``:

        Hostname, MeasuredAt, NumCPU, OpsPerSecPerCore, OpsPerSecSaturated,
        IterationTime

    Since the struct carries no ``toml:"..."`` tags, the TOML keys are
    exactly these Go field names, and the file is plain, flat TOML -- no
    nesting, no version field, no scheme name. This function just parses it;
    callers that need ``OpsPerSecSaturated`` should index the returned dict
    and let the resulting ``KeyError`` explain a malformed/wrong file.
    """
    data = tomllib.loads(raw.decode("utf-8"))
    if "OpsPerSecSaturated" not in data:
        raise KeyError(
            "selfcheck.toml missing 'OpsPerSecSaturated' -- is this really a "
            "replica self-check cache file (core/selfcheckcache/cache.go)?"
        )
    return data


def system_ctidh_ops_per_sec(saturated_ops_per_replica: list) -> float:
    """Aggregate real CTIDH throughput across replicas.

    Sums each replica's measured ``OpsPerSecSaturated`` -- the NumCPU-goroutine
    saturated measurement (``replica/selfcheck.go``'s "saturated" mode), not
    the single-goroutine "solo" figure. ``selfcheck.go`` documents saturated
    as "the realistic ceiling for one replica process when its own request
    handlers ... are fully utilising the host", which is exactly the regime a
    concurrent-users estimate needs.
    """
    return float(sum(saturated_ops_per_replica))


def default_decaps_per_request(num_replicas: int) -> tuple:
    """Return (min, typical, max) CTIDH Decapsulate ops one client pigeonhole
    request costs, replica-set-wide.

    ``pigeonhole/pki.go``'s ``GetRandomIntermediateReplicas`` always sends a
    request to exactly 2 intermediate replicas (the wire format's
    ``IntermediateReplicas [2]uint8`` is a fixed property of the current
    hash-based sharding design, not an operator-tunable K); each intermediate
    independently calls Decapsulate, so 2 ops are always paid at minimum.

    For ``num_replicas < 4`` (``pigeonhole/pki.go``'s ``numReplicas == 2`` and
    ``numReplicas == 3`` branches), the 2 intermediates ARE the real K=2 shard
    holders, so those 2 ops are the whole cost.

    For ``num_replicas >= 4`` (``pigeonhole/pki.go:170-183``), intermediates
    are chosen to EXCLUDE the shard holders, so every request also gets
    proxied to the shard holders (``replica/handlers.go``'s ``proxyToShard``),
    each of which does its own Encapsulate+Decapsulate: 2 more ops in the
    happy path (4 typical), up to 2 additional retries under failover
    (bounded by K=2, ``replica/handlers.go``'s proxy-sweep retry loop), for a
    worst case of 6.
    """
    if num_replicas < 4:
        return (2, 2, 2)
    return (4, 4, 6)


def concurrent_users_ceiling(
    system_ops_per_sec: float,
    decaps_per_request: float,
    requests_per_sec_per_user: float,
) -> float:
    """How many concurrently-active users the replica set's CTIDH budget
    supports, given an assumed per-user pigeonhole request rate.

    ``requests_per_sec_per_user`` is an operator assumption, not a protocol
    constant -- pigeonhole requests share the ordinary LambdaP-paced send
    queue (``client/sender.go``) with no independent rate of their own.
    """
    if decaps_per_request <= 0:
        raise ValueError("decaps_per_request must be > 0")
    if requests_per_sec_per_user <= 0:
        raise ValueError("requests_per_sec_per_user must be > 0")
    return system_ops_per_sec / (decaps_per_request * requests_per_sec_per_user)


def replica_mesh_pps(num_replicas: int, lambda_r_events_per_ms: float) -> float:
    """Aggregate LambdaR-paced replica<->replica mesh throughput.

    Every replica dials every OTHER replica ("Connect to all replicas for
    replication purposes", ``replica/connector.go``), using the same
    LambdaR-paced ``outgoingSender`` type as courier->replica links
    (``replica/sender.go``: "outgoingSender is a sender for outgoing
    replica-to-replica connections"). The directed-link count is
    ``num_replicas * (num_replicas - 1)``.
    """
    return num_replicas * (num_replicas - 1) * lambda_r_events_per_ms * 1e3


def replica_inbound_connections(couriers: int, num_replicas: int) -> int:
    """The real number of inbound LambdaR-paced connections one replica must
    sustain: one from each courier, plus one from each of the other
    replicas. A connection/bandwidth-budget number only -- decoy traffic on
    these links costs zero CTIDH (see module docstring), so this does not
    feed into the concurrent-users ceiling.
    """
    return couriers + (num_replicas - 1)
