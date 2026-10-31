# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""Two chat clients over one simulated Pigeonhole, in virtual time."""

import os

import pytest

from pigeonhole_rns.chat import engine as eng
from pigeonhole_rns.chat import wire
from pigeonhole_rns.chat.backend import SimBackend
from pigeonhole_rns.chat.client import SyncClient

STEP = 1000


def settle(clients, ms=120_000, step=STEP):
    for _ in range(ms // step):
        for c in clients:
            c.run(step)


def texts(c, chat):
    return [c.plain(chat, l) for l in c.lines(chat) if l.notice is None]


def notices(c, chat):
    return [l.notice.kind for l in c.lines(chat) if l.notice is not None]


@pytest.fixture
def world(tmp_path):
    sim = SimBackend(max_plaintext=1000)
    clock = [0]

    def make(name):
        return SyncClient(str(tmp_path / name), name, sim, clock=clock)

    return sim, clock, make


def test_wire_roundtrip():
    m = wire.Message(content=wire.text_content(bytes(32), "hi"))
    box = wire.box_of(m)
    assert box[:1] == b"F"
    back = wire.message_of(box)
    assert back.content == m.content and wire.text_of(back.content) == "hi"
    intro = wire.Message(introduction=wire.Introduction("bob", bytes(136)), numbers=((1, None),))
    back = wire.message_of(wire.box_of(intro))
    assert back.content is None and back.introduction.name == "bob" and back.numbers == ((1, None),)


def join(make, sim):
    """alice founds g; bob joins through a voucher alice inducts."""
    alice, bob = make("alice"), make("bob")
    alice.start()
    bob.start()
    alice.feed(eng.Create("g", "g"))
    bob.feed(eng.Join("g", "g"))
    settle([alice, bob], 10_000)
    code = open(os.path.join(bob.store.dir, "voucher-g.txt")).read().strip()
    assert "voucher_minted" in notices(bob, "g")
    alice.feed(eng.Induct("g", code))
    settle([alice, bob], 60_000)
    assert "added" in notices(alice, "g"), notices(alice, "g")
    assert "joined" in notices(bob, "g"), notices(bob, "g")
    return alice, bob


def test_join_and_chat(world):
    sim, clock, make = world
    alice, bob = join(make, sim)
    assert [n for _, n in alice.members("g")] == ["alice", "bob"]
    assert sorted(n for _, n in bob.members("g")) == ["alice", "bob"]

    alice.feed(eng.Send("g", "hello bob"))
    settle([alice, bob], 30_000)
    assert texts(bob, "g") == ["alice: hello bob"]
    bob.feed(eng.Send("g", "hey alice"))
    settle([alice, bob], 30_000)
    assert texts(alice, "g") == ["alice: hello bob", "bob: hey alice"]
    # bob's reply acknowledged alice's box.
    line = [l for l in alice.lines("g") if l.notice is None][0]
    assert line.status == eng.SENT and alice.state.chat("g").acknowledged(line)
    alice.close()
    bob.close()


def test_restart_keeps_state_and_reads_on(world):
    sim, clock, make = world
    alice, bob = join(make, sim)
    alice.feed(eng.Send("g", "one"))
    settle([alice, bob], 30_000)
    bob.close()
    alice.feed(eng.Send("g", "two"))
    settle([alice], 10_000)
    bob = make("bob")
    bob.start()
    settle([alice, bob], 30_000)
    assert texts(bob, "g") == ["alice: one", "alice: two"]
    alice.close()
    bob.close()


def test_write_retries_and_rewrite_after_epoch(world):
    sim, clock, make = world
    alice, bob = join(make, sim)
    sim.fail_next.add("write")
    alice.feed(eng.Send("g", "flaky"))
    # The write is tried again after 5s; bob's reads of a quiet stream have backed off to a minute.
    settle([alice, bob], 120_000)
    assert texts(bob, "g") == ["alice: flaky"]
    # The next epoch: alice backfills nothing bob acknowledged, and nothing is lost.
    before = sim.writes
    alice.feed(eng.Epoch(2))
    bob.feed(eng.Epoch(2))
    settle([alice, bob], 30_000)
    assert texts(bob, "g") == ["alice: flaky"]
    assert sim.writes >= before
    alice.close()
    bob.close()


def test_third_member_through_bob(world):
    sim, clock, make = world
    alice, bob = join(make, sim)
    carol = make("carol")
    carol.start()
    carol.feed(eng.Join("g", "g"))
    settle([alice, bob, carol], 10_000)
    code = open(os.path.join(carol.store.dir, "voucher-g.txt")).read().strip()
    bob.feed(eng.Induct("g", code))
    settle([alice, bob, carol], 90_000)
    assert "joined" in notices(carol, "g")
    assert sorted(n for _, n in alice.members("g")) == ["alice", "bob", "carol"], alice.members("g")
    carol.feed(eng.Send("g", "hi all"))
    settle([alice, bob, carol], 60_000)
    assert "carol: hi all" in texts(alice, "g")
    assert "carol: hi all" in texts(bob, "g")
    for c in (alice, bob, carol):
        c.close()


def test_scan_and_remove(world):
    sim, clock, make = world
    alice, bob = join(make, sim)
    alice.feed(eng.Send("g", "x"))
    settle([alice, bob], 30_000)
    bob.feed(eng.Scan("g"))
    settle([alice, bob], 30_000)
    assert "scanning" in notices(bob, "g")
    assert texts(bob, "g") == ["alice: x"]
    bob_key = [k for k, n in alice.members("g") if n == "bob"][0]
    alice.feed(eng.RemoveMember("g", bob_key))
    assert "stopped_reading" in notices(alice, "g")
    assert [n for _, n in alice.members("g")] == ["alice"]
    alice.close()
    bob.close()
