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

## Tuning the proxy path (as replica operator)

A replica that is not a shard holder for a box proxies the request to a
holder, failing over to the co-holder if the first does not answer. Two
config fields govern that, and both are best left unset so the runtime
derives them from the CTIDH self-check at startup.

- `ProxyRequestTimeout` is the budget for a whole proxied request across
  every holder tried, **not** a per-holder timeout. The remainder is
  divided among the candidates still to try, so a client waits this long
  in total and a slow first holder still leaves time to fail over. It
  also covers each attempt's CTIDH1024 encapsulation, so it must stay
  well above K times the per-attempt crypto cost.
- `ProxyWorkerCount` caps concurrent attempts. A slot covers one attempt
  against one holder, including its crypto, so the `runtime.NumCPU`
  default caps concurrent CTIDH at roughly one per core.

Four metrics tell you which bound is biting:

| Metric | Reading |
|---|---|
| `katzenpost_replica_proxy_active_attempts` | attempts holding a slot. Pinned at `ProxyWorkerCount` means the pool is the constraint. |
| `katzenpost_replica_proxy_sem_waiters` | attempts queued for a slot. Above zero while peers are alive means proxying to healthy holders is stuck behind a sick one. |
| `katzenpost_replica_proxy_pending_requests` | requests on the wire awaiting a reply. |
| `katzenpost_replica_proxy_request_timeouts_total` | per-peer count of holders that did not answer in time. |

Read the first two together: active at the cap with waiters above zero is
saturation, and wants a larger `ProxyWorkerCount` or more cores. Waiters
above zero with active below the cap means slots are turning over and
something else is slow, usually a peer.
