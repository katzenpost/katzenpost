# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
import os

import pytest

from pigeonhole_rns import wire


def test_read_roundtrip():
    box = os.urandom(32)
    q = wire.decode_query(wire.encode_read(box))
    assert q.kind == wire.READ and q.box_id == box and q.signature is None


def test_write_roundtrip():
    box, sig, ct = os.urandom(32), os.urandom(64), os.urandom(100)
    q = wire.decode_query(wire.encode_write(box, sig, ct))
    assert (q.kind, q.box_id, q.signature, q.ciphertext) == (wire.WRITE, box, sig, ct)


def test_tombstone_write_has_empty_ciphertext():
    q = wire.decode_query(wire.encode_write(os.urandom(32), os.urandom(64), b""))
    assert q.ciphertext == b""


def test_reply_roundtrip():
    sig, ct = os.urandom(64), os.urandom(20)
    r = wire.decode_reply(wire.encode_reply(wire.SUCCESS, sig, ct))
    assert (r.code, r.signature, r.ciphertext) == (wire.SUCCESS, sig, ct)
    assert wire.decode_reply(wire.encode_reply(wire.TOMBSTONE)) == wire.Reply(wire.TOMBSTONE)


@pytest.mark.parametrize("bad", [b"", b"\x00" + b"x" * 31, b"\x07" + b"x" * 32, b"\x01" + b"x" * 40])
def test_malformed_queries(bad):
    with pytest.raises(wire.WireError):
        wire.decode_query(bad)


def test_frames_over_a_socketpair():
    import socket

    a, b = socket.socketpair()
    payload = os.urandom(5000)
    wire.write_frame(a, payload)
    assert wire.read_frame(b) == payload
    a.close()
    b.close()
