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
