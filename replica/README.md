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

## dependencies

Note that this component might be slightly more tricky to build than
the rest of Katzenpost because of the dependency on a slightly older
version of RocksDB in order to maintain compatibility with the golang
bindings.

RocksDB is still currently required: it is used only to read the
legacy `<DataDir>/replica.db` database so that it can be migrated to
Pebble on startup. It will be removed in a future release once
existing deployments have been migrated.

### Migrating to Pebble

The migration runs once, on the first boot of a Pebble-backed replica,
and is recorded by a marker in the metadata database. Two things are
worth knowing before you upgrade:

- **Free space.** The copy runs while `replica.db` is still on disk, so
  the data directory needs room for a second copy of it. The replica
  checks this before starting the migration and refuses to proceed if
  the space is not there.
- **Rolling back is not free.** After a successful migration nothing
  writes to `replica.db` again. Reverting to a RocksDB build will serve
  the data as it stood at migration time, and re-upgrading afterwards
  will not recover anything written during the rollback window, because
  the migration marker is already recorded and the migration will not
  run a second time. If you need to roll back and keep the intervening
  writes, take a copy of the Pebble databases first.

## building / running

Install the `RocksDB` dependencies on your host system.
Run these commands as root:

```bash
apt install cmake

cd /tmp && \
    git clone https://github.com/gflags/gflags.git && \
    cd gflags && \
    mkdir build && \
    cd build && \
    cmake -DBUILD_SHARED_LIBS=1 -DGFLAGS_INSTALL_SHARED_LIBS=1 .. && \
    make install && \
    cd /tmp && \
    rm -R /tmp/gflags/

cd /tmp && \
    git clone https://github.com/facebook/rocksdb.git && \
    cd rocksdb && \
    git checkout v10.2.1 && \
    make shared_lib && \
    mkdir -p /usr/local/rocksdb/lib && \
    mkdir -p /usr/local/rocksdb/include && \
    cp librocksdb.so* /usr/local/rocksdb/lib && \
    cp /usr/local/rocksdb/lib/librocksdb.so* /usr/lib/ && \
    cp -r include /usr/local/rocksdb/ && \
    cp -r include/* /usr/include/ && \
    rm -R /tmp/rocksdb/
```

and then you can run `go build` as usual:

```bash
cd cmd/replica
go build
```

## Debugging (as replica operator)

Box records now live in a Pebble database at `<DataDir>/replica-boxes.db`
(with a small `<DataDir>/replica-metadata.db` for bookkeeping such as the
rebalance fingerprint). The legacy RocksDB `<DataDir>/replica.db` is
retained only as the migration source during the intermediate release and
is removed in a later release.

```shell
# Pebble's CLI can inspect the box keyspace. It opens the database
# read-write and therefore takes the same lock as a running replica, so
# stop the replica first:
for i in {1..5}; do echo "Replica $i"; go run github.com/cockroachdb/pebble/cmd/pebble@v1.1.5 db scan voting_mixnet/replica${i}/replica-boxes.db; done
```

For a pre-migration deployment that still has a RocksDB `replica.db`:

```shell
apt install rocksdb-tools/testing
```

```shell
for i in {1..5}; do echo "Replica $i"; ldb --db=voting_mixnet/replica${i}/replica.db --hex --ignore_unknown_options dump | awk -F '==' '/==/ {print "\t"$1}'; done
```

```
Replica 1
        0x3B0B39B05170202479198C5D63A7D8A2A30FF3D17A0C20EBCF4FF124A7D56DBC 
        0xA9F171DCEE449B661CFDDCDAAF82E9808628BF105E2144AA779CFDA30C6B180A 
Replica 2
        0xA9F171DCEE449B661CFDDCDAAF82E9808628BF105E2144AA779CFDA30C6B180A 
Replica 3
Replica 4
        0xA9F171DCEE449B661CFDDCDAAF82E9808628BF105E2144AA779CFDA30C6B180A 
Replica 5
        0x3B0B39B05170202479198C5D63A7D8A2A30FF3D17A0C20EBCF4FF124A7D56DBC 
        0xA9F171DCEE449B661CFDDCDAAF82E9808628BF105E2144AA779CFDA30C6B180A
```
