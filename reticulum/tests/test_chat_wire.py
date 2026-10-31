# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""The wire formats against the vectors katzenqt generated, copied from
pigeonhole_protocols (testdata/SOURCES): each message reads as katzenqt
reads it and is written as katzenqt writes it, each reply carries the
JoinReply katzenqt takes from it, and the acks codec agrees."""

import json
import os

import pytest

from pigeonhole_rns.chat import wire
from pigeonhole_rns.chat.member import ack_codec

HERE = os.path.dirname(os.path.abspath(__file__))


def load(name):
    with open(os.path.join(HERE, "testdata", name)) as f:
        return json.load(f)


def unhex(s):
    return None if s is None else bytes.fromhex(s)


def message_json(m):
    if m is None:
        return None
    return {
        "content": None if m.content is None else m.content.hex(),
        "introduction": None if m.introduction is None else {"name": m.introduction.name, "read_cap": m.introduction.read_cap.hex()},
        "numbers": [[i, None if p is None else p.hex()] for i, p in m.numbers],
        "introduced_at": None if m.introduced_at is None else {"introducer": m.introduced_at.introducer, "index": m.introduced_at.index.hex()},
        "acks": [[k, v] for k, v in sorted(m.acks.items())],
    }


def read_message(j):
    return wire.Message(
        content=unhex(j["content"]),
        introduction=None if j["introduction"] is None else wire.Introduction(j["introduction"]["name"], unhex(j["introduction"]["read_cap"])),
        numbers=tuple((i, unhex(p)) for i, p in j["numbers"]),
        introduced_at=None if j["introduced_at"] is None else wire.IntroRef(j["introduced_at"]["introducer"], unhex(j["introduced_at"]["index"])),
        acks={k: v for k, v in j["acks"]},
    )


V = load("groupchat_wire_vectors.json")


@pytest.mark.parametrize("e", V["messages"], ids=[e["name"] for e in V["messages"]])
def test_message_reads_and_writes_back(e):
    cbor = unhex(e["cbor"])
    got = wire.to_message(cbor)
    want = e["message"]
    if want is None:
        assert got is None
        assert e.get("rewritten") is None
        return
    assert got is not None
    assert message_json(got) == {k: v for k, v in want.items() if k != "membership_hash"}
    assert wire.stamp_of(cbor) == unhex(want["membership_hash"])
    rewritten = unhex(e["rewritten"])
    assert wire.of_message(got, wire.stamp_of(cbor)).encode() == rewritten
    if rewritten == cbor:
        assert wire.decode_gcm(cbor).encode() == cbor


@pytest.mark.parametrize("e", V["written"], ids=[e["name"] for e in V["written"]])
def test_message_is_written_as_katzenqt_writes_it(e):
    m = read_message(e["message"])
    assert wire.box_of(m, unhex(e["message"]["membership_hash"])) == unhex(e["box"])


@pytest.mark.parametrize("e", V["membership"])
def test_membership_hash(e):
    assert wire.membership_hash([unhex(c) for c in e["read_caps"]]) == unhex(e["hash"])


@pytest.mark.parametrize("e", V["replies"], ids=[e["name"] for e in V["replies"]])
def test_reply_carries_join_reply(e):
    w = wire.reply_who_decode(unhex(e["cbor"]))
    assert w is not None
    r = wire.to_join_reply(w)
    want = e["join_reply"]
    if want is None:
        assert r is None
        return
    assert r is not None
    assert [None if m is None else [m[0].hex(), m[1].hex()] for m in r.members] == want["members"]
    assert [None if ro is None else [[i, s] for i, s in ro] for ro in r.rosters] == want["rosters"]
    assert [[b, i.hex(), m] for b, i, m in r.introductions] == want["introductions"]
    assert r.introducer == want["introducer"] and r.newcomer == want["newcomer"]
    # And written again, it reads the same.
    again = wire.reply_who_decode(wire.reply_who_encode(r, lambda key: next(p[0] for p in w.please_adds if p is not None and wire.key_of(p[1]) == key)))
    assert wire.to_join_reply(again) == r


A = load("acks_vectors.json")


@pytest.mark.parametrize("e", A["valid"], ids=[e["name"] + "-" + e["field"][:6] for e in A["valid"]])
def test_acks_valid(e):
    acks = {k: v for k, v in e["acks"]}
    assert ack_codec.encode(acks).hex() == e["field"]
    assert ack_codec.decode(unhex(e["field"])) == acks


@pytest.mark.parametrize("e", A["lenient"], ids=[e["name"] + "-" + e["field"][:6] for e in A["lenient"]])
def test_acks_lenient(e):
    assert ack_codec.decode(unhex(e["field"])) == {k: v for k, v in e["acks"]}


@pytest.mark.parametrize("e", A["malformed"], ids=[e.get("name", "") + "-" + e["field"][:6] for e in A["malformed"]])
def test_acks_malformed(e):
    with pytest.raises(ack_codec.AcksError):
        ack_codec.decode(unhex(e["field"]))
