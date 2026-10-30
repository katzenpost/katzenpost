# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
import os

from pigeonhole_rns import wire
from pigeonhole_rns.store import Store


def test_write_once_and_idempotent(tmp_path):
    s = Store(str(tmp_path / "s.sqlite"))
    box, sig, ct = os.urandom(32), os.urandom(64), os.urandom(50)
    assert s.put(box, sig, ct, 7) == wire.SUCCESS
    assert s.put(box, sig, ct, 7) == wire.SUCCESS
    assert s.put(box, os.urandom(64), os.urandom(50), 7) == wire.ALREADY_EXISTS
    assert s.get(box).payload == ct


def test_tombstone_replaces_and_is_final(tmp_path):
    s = Store(str(tmp_path / "s.sqlite"))
    box, sig, ct = os.urandom(32), os.urandom(64), os.urandom(50)
    s.put(box, sig, ct, 7, dsts=[b"r2"])
    s.ack(box, b"r2")
    tsig = os.urandom(64)
    assert s.put(box, tsig, b"", 7) == wire.SUCCESS
    assert s.get(box).is_tombstone
    assert s.acked(box) == set(), "a tombstone starts its own acknowledgements"
    assert s.put(box, sig, ct, 7) == wire.ALREADY_EXISTS
    assert s.get(box).is_tombstone
    s.drop(box)
    assert s.get(box).is_tombstone, "tombstones are never dropped"


def test_put_enqueues_atomically(tmp_path):
    s = Store(str(tmp_path / "s.sqlite"))
    box = os.urandom(32)
    s.put(box, os.urandom(64), os.urandom(50), 7, dsts=[b"r2", b"r3"])
    assert {d for _, d, _ in s.due(0)} == {b"r2", b"r3"}
    s.ack(box, b"r2")
    assert s.queued(box) == {b"r3"}
    assert s.acked(box) == {b"r2"}
    s.backoff(box, b"r3", 1000.0)
    assert s.due(999.0) == []
    assert [(b, d, n) for b, d, n in s.due(1000.0)] == [(box, b"r3", 1)]


def test_sweep_keeps_the_window(tmp_path):
    s = Store(str(tmp_path / "s.sqlite"))
    old, cur = os.urandom(32), os.urandom(32)
    s.put(old, os.urandom(64), os.urandom(50), 5, dsts=[b"r2"])
    s.put(cur, os.urandom(64), os.urandom(50), 7)
    assert s.sweep([7, 6]) == 1
    assert s.get(old) is None and s.get(cur) is not None
    assert s.queued(old) == set()
