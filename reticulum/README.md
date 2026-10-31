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

## Group chat

`pigeonhole_rns.chat` is katzenqt's group chat protocol over mesh boxes,
so a group can have members on a mixnet running katzenqt and members on a
mesh running this. The member state machine is katzenqt's own, copied
unchanged from `katzenqt/src/katzenqt/groupchat` (`chat/member/SOURCES`
names the commit), so cryptlib's proofs and trace replay apply to it here
too. Around it: the wire formats (`chat/wire.py`), a client without IO after
pigeonhole_protocols' engine (`chat/engine.py`), a backend over the mesh
client or in memory (`chat/backend.py`), SQLite state (`chat/store.py`) and
the client that carries the engine's work out on threads (`chat/client.py`).

    pigeonhole-chat --config ~/.reticulum --state ~/chat --name alice --box-size 1000

reads commands on standard input (`create g`, `join g`, `induct g CODE`,
`send g hello`, `show g`, `members g`, `scan g`) and prints lines as they
arrive. Joining is by contact voucher: the joiner's `join` mints a code,
written to `voucher-g.txt` under its state directory, which a member pastes
into `induct`. Messages that do not fit one box are not sent yet.

## Test

    pytest
    python tests/e2e_two_replicas.py --run-dir /some/scratch/dir
    python tests/e2e_chat.py --run-dir /some/scratch/dir

The end to end tests start two replica processes on a local TCP interface.
The first drives a client through write, read, forward, delete and
tombstone; the second runs two chat clients through founding a group,
joining by voucher and talking. `tests/test_chat.py` runs the same chat
flows in process against a simulated Pigeonhole in virtual time.

## Bridge test against the docker mixnet

    make -C docker start wait
    make -C docker reticulum-test

`genconfig --bridgeReplica 1`, which the docker Makefile passes by default,
gives replica1 a bridge socket in its DataDir. `reticulum-test` starts a
container on the host network running a mesh replica bridged to that
socket and `tests/docker_bot.py`, then runs `TestReticulumBridge` in
`client/`: a mixnet client writes a box, drops a job for the bot, the bot
reads the box through the mesh (pulled over the bridge) and answers on
another stream (pushed over the bridge), and the mixnet client reads the
answer.
