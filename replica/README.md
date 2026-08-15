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

## Is this replica keeping up? (as replica operator)

Nothing on the proxy path is meant to be tuned by hand. `ProxyWorkerCount`,
`ProxyRequestTimeout` and `IncomingQueueSize` should be absent from your TOML
so the runtime derives them at startup from `runtime.NumCPU` and the CTIDH
self-check it runs on your actual host. Setting them explicitly overrides that
measurement with a guess, and is intended only for research workloads and
deliberate chaos testing.

Reaching for `ProxyWorkerCount` in particular is a trap that has already been
sprung once. An earlier revision let operators shrink it on co-tenanted hosts,
on the reasonable-sounding intuition that fewer workers would reduce CPU
contention. Measured under parallel load it did the opposite: throughput fell
2.5x and p99 latency rose 12x, because the application-layer semaphore
serialises pipeline parallelism far more aggressively than CPU contention ever
would. The OS scheduler shares cores perfectly well. The reasoning is preserved
in full at `ApplyRuntimeDefaults` in `config/config.go`.

The metrics below are therefore for diagnosis, not for feeding back into
config. They answer one question: is this replica keeping up?

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
  CTIDH. The remedy is a bigger host, not a bigger number: the self-check
  already sized the pool to the cores it found.
- **Both at zero.** The proxy path is idle whatever else is wrong.

If replicas across the fleet are saturated at once, the problem is not any one
node's configuration. It means the offered load has caught up with the
provisioned LambdaR, which is a consensus parameter set by the directory
authorities and deliberately an over-provisioning decision made once, for a
target population, rather than tuned against measured demand. See §6 of the
Pigeonhole courier and replica decoy traffic design. Chasing it with per-node
config would only move the queue somewhere less visible.
