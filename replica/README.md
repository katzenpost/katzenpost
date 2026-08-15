# Pigeonhole Storage Replica

This section of code implements the storage replica server from our
unpublished paper, **Echomix: a Strong Anonymity System with
Messaging** which you can read here: https://arxiv.org/abs/2501.02933

This storage server operates "outside the mixnet". The "courier"
services which operates on the service nodes in the mix network, is
responsible for proxying queries and replies to and from the storage
replicas. The replicas perform their replication and communication
with the courier services outside of the mixnet, however they do make
use of our PQ Noise based transport protocol for all of this
communication. Detailed design docs forthcoming.

## building / running

The replica is pure Go and builds like any other component:

```bash
cd cmd/replica
go build
```

## Debugging (as replica operator)

Box records live in a Pebble database at `<DataDir>/replica-boxes.db`
(with a small `<DataDir>/replica-metadata.db` for bookkeeping such as the
rebalance fingerprint).

```shell
# Pebble's CLI can inspect the box keyspace. It opens the database
# read-write and therefore takes the same lock as a running replica, so
# stop the replica first:
for i in {1..5}; do echo "Replica $i"; go run github.com/cockroachdb/pebble/cmd/pebble@v1.1.5 db scan voting_mixnet/replica${i}/replica-boxes.db; done
```

## Self-tuning (as replica operator)

The replica sizes its own proxy path. There is nothing here to configure.

At startup it measures what this host can actually do, timing MKEM
(CTIDH1024-X25519) decapsulation both solo and with `runtime.NumCPU` goroutines
in parallel, and derives `ProxyWorkerCount`, `ProxyRequestTimeout` and
`IncomingQueueSize` from the result. The measurement is cached in a sidecar file
beside the database and re-taken automatically when `runtime.NumCPU` or the
hostname changes, so moving the replica to a different machine re-sizes it
without anyone being told to go and edit a TOML. Delete the sidecar to force a
fresh measurement. The derivations, and the reasoning behind each, are at
`ApplyRuntimeDefaults` in `config/config.go`.

Those three fields do exist in the config schema, and setting any of them
replaces a measurement of your host with a guess about it. They are there for
research workloads and deliberate chaos testing. `ProxyWorkerCount` is the
tempting one and the one to leave alone hardest: an earlier revision let
operators shrink it on co-tenanted hosts, and measured under parallel load that
cost 2.5x throughput and 12x p99 latency, because the semaphore serialises
pipeline parallelism far more aggressively than CPU contention does.

## Is this replica keeping up?

These metrics are for watching health, not for feeding back into config.

| Metric | Reading |
|---|---|
| `katzenpost_replica_proxy_active_attempts` | attempts holding a worker slot |
| `katzenpost_replica_proxy_sem_waiters` | attempts queued for a slot |
| `katzenpost_replica_proxy_pending_requests` | requests on the wire awaiting a reply |
| `katzenpost_replica_proxy_request_timeouts_total` | per-peer count of holders that did not answer in time |

Read the first two together:

- **Waiters above zero, active below the cap.** Slots are turning over, so this
  replica is not the constraint. Something it depends on is slow, and the
  per-peer timeout counter usually names it.
- **Waiters above zero, active pinned at the cap.** This replica is CPU-bound on
  CTIDH, and wants more cores. It has already sized itself to the ones it has.
- **Both at zero.** The proxy path is idle whatever else is wrong.

If replicas across the fleet saturate at once, no node's configuration is at
fault. It means offered load has caught up with the provisioned LambdaR, a
consensus parameter the directory authorities set as a deliberate
over-provisioning decision for a target population, never derived from measured
demand. See §6 of the Pigeonhole courier and replica decoy traffic design.
