# Pigeonhole over Reticulum

A Pigeonhole storage replica and client for Reticulum mesh networks, in pure
Python on the RNS library, and the mesh half of a bridge to a Katzenpost
mixnet. The design is the Pigeonhole over Reticulum specification on the
Katzenpost website; this is its open mesh profile.

A replica is any node that announces `pigeonhole.replica`. Boxes are placed
by rendezvous hashing over the replicas a node has heard, two owners per
box; an entry replica stores a client's write, acknowledges, and forwards
along the box's order, standing in for owners it cannot reach and handing
off when it can. Reads walk the order past the owners. Boxes are BACAP boxes
verified with `hpqc.bacap`, the same object the mixnet stores.

## Install

    pip install rns
    pip install /path/to/hpqc/py      # the hpqc Python port
    pip install -e .

## Run a replica

    pigeonhole-rns --config ~/.reticulum --box-size 1000 replica --storage ~/pigeonhole

`--box-size` is the box plaintext size and must be the same on every replica
and, through a bridge, equal to the mixnet's. A bridge adds
`--bridge-socket /path/to/replica/bridge.sock`, the `BridgeSocket` of a
Katzenpost replica on the same host.

## Use it

    pigeonhole-rns new-cap
    pigeonhole-rns --config ~/.reticulum write --writecap <hex> --index 0 "yo what up"
    pigeonhole-rns --config ~/.reticulum read  --readcap <hex>  --index 0

## Test

    pytest
    python tests/e2e_two_replicas.py --run-dir /some/scratch/dir

The end to end test starts two replica processes on a local TCP interface
and drives a client through write, read, forward, delete and tombstone.
