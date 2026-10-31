# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""The replica's decisions, free of Reticulum so they can be tested in
process: membership, placement, the entry path, forwarding, handoff, the
read walk and the bridge."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable, Dict, Iterable, List, Optional, Set

from hpqc.bacap.stateless import MessageBoxIndex

from . import placement, wire
from .store import Store

# A pseudo destination for the local Katzenpost replica on a bridge node.
BRIDGE = b"bridge"

EPOCH_SECONDS = 7 * 24 * 3600
# Katzenpost replicas count epochs from 2017-06-01 UTC; a bridged box must
# fall in the same epoch on both sides.
EPOCH_BASE = 1496275200

# Retry backoff for forwards, in seconds.
BACKOFF_BASE = 5.0
BACKOFF_CAP = 600.0


def epoch_now(now: Optional[float] = None) -> int:
    return int(((time.time() if now is None else now) - EPOCH_BASE) // EPOCH_SECONDS)


@dataclass
class Peer:
    identity: bytes
    bridge: bool = False
    last_heard: float = 0.0


# Callbacks the Reticulum layer supplies.
Deliver = Callable[[bytes, bytes, bytes, bytes], Optional[int]]  # (dst, box_id, sig, ct) -> code or None
Peek = Callable[[bytes, bytes], Optional[wire.Reply]]  # (dst, box_id) -> reply or None on no answer
BridgeRead = Callable[[bytes], Optional[wire.Reply]]  # (box_id) -> reply or None


class Engine:
    def __init__(
        self,
        store: Store,
        self_dest: bytes,
        self_identity: bytes,
        box_ciphertext_size: Optional[int] = None,
        k: int = placement.K,
        is_bridge: bool = False,
        now: Callable[[], float] = time.time,
    ):
        self.store = store
        self.self_dest = self_dest
        self.k = k
        self.is_bridge = is_bridge
        self.box_ciphertext_size = box_ciphertext_size
        self.now = now
        self.peers: Dict[bytes, Peer] = {self_dest: Peer(self_identity, is_bridge)}

    # ---- membership ----

    def heard(self, dest: bytes, identity: bytes, bridge: bool) -> bool:
        """Records an announce. A changed identity for a known destination
        is ignored, so the first key seen is the one kept."""
        cur = self.peers.get(dest)
        if cur is not None and cur.identity != identity:
            return False
        self.peers[dest] = Peer(identity, bridge, self.now())
        return True

    def identity_of(self, dest: bytes) -> bytes:
        return self.peers[dest].identity

    def owners(self, box_id: bytes) -> List[bytes]:
        return placement.first(box_id, self.peers.keys(), self.identity_of, self.k)

    def targets(self, box_id: bytes, reachable: Iterable[bytes]) -> List[bytes]:
        cands = set(reachable) | {self.self_dest}
        return placement.first(box_id, cands, self.identity_of, self.k)

    def bridges(self, reachable: Iterable[bytes]) -> List[bytes]:
        return [d for d in reachable if d in self.peers and self.peers[d].bridge and d != self.self_dest]

    # ---- verification ----

    def verify(self, q: wire.Query) -> int:
        assert q.signature is not None and q.ciphertext is not None
        if len(q.ciphertext) != 0 and self.box_ciphertext_size is not None and len(q.ciphertext) != self.box_ciphertext_size:
            return wire.INVALID_PAYLOAD
        try:
            ok = MessageBoxIndex.verify_box(q.box_id, q.ciphertext, q.signature)
        except Exception:
            return wire.INVALID_BOX_ID
        return wire.SUCCESS if ok else wire.INVALID_SIGNATURE

    # ---- the entry path ----

    def accept(self, q: wire.Query, reachable: Iterable[bytes]) -> int:
        """Verify, store, and enqueue forwards to the first k reachable in
        the box's order, and to the local Katzenpost replica on a bridge."""
        code = self.verify(q)
        if code != wire.SUCCESS:
            return code
        dsts = [d for d in self.targets(q.box_id, reachable) if d != self.self_dest]
        if self.is_bridge:
            dsts.append(BRIDGE)
        return self.store.put(q.box_id, q.signature, q.ciphertext, epoch_now(self.now()), dsts)

    def handle_write(self, data: bytes, reachable: Iterable[bytes]) -> bytes:
        try:
            q = wire.decode_query(data)
        except wire.WireError:
            return wire.encode_reply(wire.INVALID_PAYLOAD)
        if q.kind != wire.WRITE:
            return wire.encode_reply(wire.INVALID_PAYLOAD)
        return wire.encode_reply(self.accept(q, reachable))

    # ---- reads ----

    def local(self, box_id: bytes) -> Optional[wire.Reply]:
        box = self.store.get(box_id)
        if box is None:
            return None
        if box.is_tombstone:
            return wire.Reply(wire.TOMBSTONE)
        return wire.Reply(wire.SUCCESS, box.signature, box.payload)

    def handle_peek(self, data: bytes, bridge_read: Optional[BridgeRead] = None) -> bytes:
        """A replica asking a replica: this store only, plus the mixnet on a
        bridge. Never walks, so replicas cannot chase each other."""
        try:
            q = wire.decode_query(data)
        except wire.WireError:
            return wire.encode_reply(wire.INVALID_PAYLOAD)
        if q.kind != wire.READ:
            return wire.encode_reply(wire.INVALID_PAYLOAD)
        r = self.local(q.box_id)
        if r is None and self.is_bridge and bridge_read is not None:
            r = self._pull(q.box_id, bridge_read)
        if r is None:
            return wire.encode_reply(wire.NOT_FOUND)
        return wire.encode_reply(r.code, r.signature, r.ciphertext)

    def handle_read(self, data: bytes, reachable: Iterable[bytes], peek: Peek, bridge_read: Optional[BridgeRead] = None) -> bytes:
        """A client asking its entry replica: this store, then every reachable
        replica in the box's order past the owners, then a bridge."""
        try:
            q = wire.decode_query(data)
        except wire.WireError:
            return wire.encode_reply(wire.INVALID_PAYLOAD)
        if q.kind != wire.READ:
            return wire.encode_reply(wire.INVALID_PAYLOAD)
        reachable = list(reachable)
        r = self.local(q.box_id)
        if r is None:
            for dst in placement.order(q.box_id, [d for d in reachable if d != self.self_dest and d in self.peers], self.identity_of):
                got = peek(dst, q.box_id)
                if got is not None and got.code in (wire.SUCCESS, wire.TOMBSTONE):
                    r = got
                    break
        if r is None and self.is_bridge and bridge_read is not None:
            r = self._pull(q.box_id, bridge_read)
        if r is None:
            for dst in self.bridges(reachable):
                got = peek(dst, q.box_id)
                if got is not None and got.code in (wire.SUCCESS, wire.TOMBSTONE):
                    r = got
                    break
        if r is None:
            return wire.encode_reply(wire.NOT_FOUND)
        if self.store.get(q.box_id) is None:
            self._adopt(q.box_id, r, reachable)
        return wire.encode_reply(r.code, r.signature, r.ciphertext)

    def _pull(self, box_id: bytes, bridge_read: BridgeRead) -> Optional[wire.Reply]:
        got = bridge_read(box_id)
        if got is not None and got.code in (wire.SUCCESS, wire.TOMBSTONE):
            return got
        return None

    def _adopt(self, box_id: bytes, r: wire.Reply, reachable: Iterable[bytes]) -> None:
        """A box fetched for a reader is stored and forwarded like a write,
        so the next reader finds it on the mesh."""
        if r.code == wire.SUCCESS and r.signature is not None:
            q = wire.Query(wire.WRITE, box_id, r.signature, r.ciphertext or b"")
            if self.verify(q) == wire.SUCCESS:
                dsts = [d for d in self.targets(box_id, reachable) if d != self.self_dest]
                self.store.put(box_id, r.signature, r.ciphertext or b"", epoch_now(self.now()), dsts)

    # ---- forwarding and handoff ----

    def forward_due(self, reachable: Iterable[bytes], deliver: Deliver) -> int:
        """Attempts every due forward whose destination is reachable.
        deliver returns the peer's reply code, or None when it did not
        answer. Returns how many were acknowledged."""
        reachable = set(reachable)
        now = self.now()
        done = 0
        for box_id, dst, attempts in self.store.due(now):
            if dst != BRIDGE and dst not in reachable:
                continue
            box = self.store.get(box_id)
            if box is None:
                self.store.forget(box_id, dst)
                continue
            code = deliver(dst, box_id, box.signature, box.payload)
            if code is not None and code in wire.STORED_CODES:
                self.store.ack(box_id, dst)
                done += 1
            elif code is not None and code in (wire.INVALID_SIGNATURE, wire.INVALID_BOX_ID, wire.INVALID_PAYLOAD):
                self.store.forget(box_id, dst)
            else:
                delay = min(BACKOFF_CAP, BACKOFF_BASE * (2 ** min(attempts, 10)))
                self.store.backoff(box_id, dst, now + delay)
        return done

    def handoff(self, reachable: Iterable[bytes]) -> int:
        """For every held box whose owners, in this replica's view, do not
        include it: enqueue to owners not yet acknowledged, and drop the
        copy once both owners have acknowledged and nothing is queued.
        Tombstones are never dropped. Returns how many copies were dropped."""
        reachable = set(reachable)
        dropped = 0
        for box_id in self.store.box_ids():
            owners = self.owners(box_id)
            if self.self_dest in owners:
                continue
            acked = self.store.acked(box_id)
            queued = self.store.queued(box_id)
            for o in owners:
                if o in reachable and o not in acked and o not in queued:
                    self.store.enqueue(box_id, o)
                    queued.add(o)
            box = self.store.get(box_id)
            if box is None or box.is_tombstone:
                continue
            if len(owners) == self.k and all(o in acked for o in owners) and not (queued - {BRIDGE}):
                self.store.drop(box_id)
                dropped += 1
        return dropped

    def gc(self) -> int:
        cur = epoch_now(self.now())
        return self.store.sweep([cur, cur - 1])
