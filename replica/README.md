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
