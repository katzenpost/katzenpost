# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""The replica's decisions, driven in process with fake peers."""
import os

from hpqc.bacap.stateless import WriteCap

from pigeonhole_rns import PIGEONHOLE_CTX, placement, wire
from pigeonhole_rns.client import pad, position
from pigeonhole_rns.engine import BRIDGE, Engine
from pigeonhole_rns.store import Store

BOX = 100
CT = BOX + 4 + 16

ME, R2, R3, R4 = b"me" * 8, b"r2" * 8, b"r3" * 8, b"r4" * 8
IDS = {ME: b"I" + ME, R2: b"I" + R2, R3: b"I" + R3, R4: b"I" + R4}


def engine(tmp_path, is_bridge=False, peers=(R2, R3, R4)):
    clock = [1000.0]
    e = Engine(Store(str(tmp_path / "e.sqlite")), ME, IDS[ME], box_ciphertext_size=CT, is_bridge=is_bridge, now=lambda: clock[0])
    e.clock = clock
    for p in peers:
        e.heard(p, IDS[p], False)
    return e


def seal(text=b"yo", index=0):
    cap = WriteCap.generate()
    pos = position(cap, index)
    box, ct, sig = pos.encrypt(PIGEONHOLE_CTX, pad(text, BOX))
    return cap, box, sig, ct


def test_order_is_shared_and_stable():
    box = os.urandom(32)
    a = placement.order(box, [ME, R2, R3], lambda d: IDS[d])
    b = placement.order(box, [R3, ME, R2], lambda d: IDS[d])
    assert a == b and set(a) == {ME, R2, R3}


def test_write_verifies_stores_and_forwards(tmp_path):
    e = engine(tmp_path)
    _, box, sig, ct = seal()
    reply = e.handle_write(wire.encode_write(box, sig, ct), reachable=[R2, R3, R4])
    assert reply == bytes([wire.SUCCESS])
    targets = {d for _, d, _ in e.store.due(0)}
    assert targets == set(e.targets(box, [R2, R3, R4])) - {ME}
    assert len(targets) <= 2

    bad = bytearray(sig)
    bad[0] ^= 1
    assert e.handle_write(wire.encode_write(box, bytes(bad), ct), []) == bytes([wire.INVALID_SIGNATURE])
    assert e.handle_write(wire.encode_write(box, sig, ct[:-1]), []) == bytes([wire.INVALID_PAYLOAD])


def test_write_is_acknowledged_even_when_alone(tmp_path):
    e = engine(tmp_path, peers=())
    _, box, sig, ct = seal()
    assert e.handle_write(wire.encode_write(box, sig, ct), reachable=[]) == bytes([wire.SUCCESS])
    assert e.store.get(box) is not None
    assert e.store.due(0) == []


def test_read_walks_past_owners(tmp_path):
    e = engine(tmp_path)
    _, box, sig, ct = seal()
    holder = {R4: wire.Reply(wire.SUCCESS, sig, ct)}
    asked = []

    def peek(dst, b):
        asked.append(dst)
        return holder.get(dst, wire.Reply(wire.NOT_FOUND))

    reply = wire.decode_reply(e.handle_read(wire.encode_read(box), [R2, R3, R4], peek))
    assert reply.code == wire.SUCCESS and reply.ciphertext == ct
    assert asked == placement.order(box, [R2, R3, R4], e.identity_of)[: asked.index(R4) + 1]
    assert e.store.get(box) is not None, "a fetched box is adopted"


def test_read_prefers_tombstone_and_reports_miss(tmp_path):
    e = engine(tmp_path)
    _, box, sig, ct = seal()
    assert wire.decode_reply(e.handle_read(wire.encode_read(box), [R2], lambda d, b: wire.Reply(wire.TOMBSTONE))).code == wire.TOMBSTONE
    assert wire.decode_reply(e.handle_read(wire.encode_read(os.urandom(32)), [R2], lambda d, b: None)).code == wire.NOT_FOUND


def test_forward_acks_and_backs_off(tmp_path):
    e = engine(tmp_path)
    _, box, sig, ct = seal()
    e.handle_write(wire.encode_write(box, sig, ct), [R2, R3, R4])
    targets = {d for _, d, _ in e.store.due(0)}
    answers = {t: wire.SUCCESS for t in targets}
    silent = next(iter(targets))
    answers[silent] = None
    e.forward_due(targets, lambda dst, b, s, c: answers[dst])
    assert e.store.acked(box) == targets - {silent}
    assert e.store.queued(box) == {silent}
    assert e.store.due(e.now()) == [], "the silent peer is backed off, not retried at once"


def test_handoff_then_drop_only_after_both_owners_ack(tmp_path):
    e = engine(tmp_path)
    _, box, sig, ct = seal()
    # Written while only this replica was reachable: no forwards queued.
    e.handle_write(wire.encode_write(box, sig, ct), reachable=[])
    owners = e.owners(box)
    if ME in owners:
        return  # this replica owns it; nothing to hand off
    e.handoff(reachable=owners)
    assert e.store.queued(box) == set(owners)
    e.forward_due(owners, lambda dst, b, s, c: wire.SUCCESS if dst == owners[0] else None)
    e.handoff(reachable=owners)
    assert e.store.get(box) is not None, "one acknowledgement is not enough"
    e.clock[0] += 3600  # past the backoff of the owner that did not answer
    e.forward_due(owners, lambda dst, b, s, c: wire.ALREADY_EXISTS)
    assert e.handoff(reachable=owners) == 1
    assert e.store.get(box) is None


def test_bridge_push_and_pull(tmp_path):
    e = engine(tmp_path, is_bridge=True)
    _, box, sig, ct = seal()
    e.handle_write(wire.encode_write(box, sig, ct), reachable=[])
    assert BRIDGE in e.store.queued(box)
    pushed = []
    e.forward_due([], lambda dst, b, s, c: pushed.append(dst) or wire.SUCCESS)
    assert pushed == [BRIDGE]

    _, other, osig, oct_ = seal(b"from the mixnet")
    mix = {other: wire.Reply(wire.SUCCESS, osig, oct_)}
    r = wire.decode_reply(e.handle_read(wire.encode_read(other), [], lambda d, b: None, bridge_read=lambda b: mix.get(b)))
    assert r.code == wire.SUCCESS and r.ciphertext == oct_
    assert e.store.get(other) is not None, "a pulled box lives on the mesh afterwards"
    assert wire.decode_reply(e.handle_peek(wire.encode_read(other))).code == wire.SUCCESS
