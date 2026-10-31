# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""What the chat client asks of Pigeonhole: boxes on streams, and the
contact vouchers a new member joins through. Caps and indexes are BACAP's
binary forms. ``MeshBackend`` is over a Reticulum mesh replica;
``SimBackend`` is in memory, for tests."""

from __future__ import annotations

import threading
from typing import Dict, Optional, Tuple

from hpqc.bacap.stateless import MessageBoxIndex, ReadCap, WriteCap
from hpqc.voucher import api as voucher

from .. import PIGEONHOLE_CTX, wire as replica_wire
from ..client import Client, pad, unpad
from ..engine import epoch_now
from .engine import DATA, NOT_FOUND, TOMBSTONE, Inducted, Keypair, Minted, Opened, Outcome


class BoxExists(Exception):
    """A write to a box that holds something else."""


class TransportError(Exception):
    """A call that may succeed if tried again."""


def next_index(index: bytes) -> bytes:
    return MessageBoxIndex.from_bytes(index).next_index().to_bytes()


def derive(start: bytes, count: int) -> Tuple[bytes, ...]:
    """The count indexes after start."""
    i = MessageBoxIndex.from_bytes(start)
    out = []
    for _ in range(count):
        i = i.next_index()
        out.append(i.to_bytes())
    return tuple(out)


class Backend:
    """Boxes and vouchers. Every call may fail with TransportError; a caller
    that must succeed retries."""

    def new_keypair(self) -> Keypair:
        wc = WriteCap.generate()
        rc = wc.read_cap()
        return Keypair(wc.to_bytes(), rc.to_bytes(), rc.to_bytes()[32:])

    def write_box(self, write_cap: bytes, index: bytes, plaintext: bytes) -> None:
        """An empty plaintext is a tombstone. Writing again what a box holds
        succeeds; writing anything else raises BoxExists."""
        raise NotImplementedError

    def read_box(self, read_cap: bytes, index: bytes) -> Outcome:
        raise NotImplementedError

    def replica_epoch(self) -> int:
        raise NotImplementedError

    def max_plaintext(self) -> int:
        raise NotImplementedError

    # Vouchers are pure computation, the same over any transport.

    def voucher_mint(self, write_cap: bytes, name: str) -> Minted:
        m = voucher.voucher_mint(write_cap, name)
        return Minted(m.voucher, m.voucher_payload, m.voucher_write_cap, m.voucher_read_cap, m.voucher_secret_key)

    def voucher_derive_stream(self, v: bytes) -> Tuple[bytes, bytes]:
        s = voucher.derive_voucher_stream(v)
        return s.voucher_write_cap, s.voucher_read_cap

    def voucher_induct(self, v: bytes, payload: bytes, who_reply: bytes) -> Inducted:
        r = voucher.voucher_induct(v, payload, who_reply)
        return Inducted(r.display_name, r.mutated_message_read_cap, r.sealed_reply)

    def voucher_open(self, secret_key: bytes, sealed_reply: bytes, write_cap: bytes) -> Opened:
        r = voucher.voucher_open_reply(secret_key, sealed_reply, write_cap)
        return Opened(r.who_reply, r.mutated_message_write_cap)


def _write_position(write_cap: bytes, index: bytes):
    return WriteCap.from_bytes(write_cap).position_at(MessageBoxIndex.from_bytes(index))


def _read_position(read_cap: bytes, index: bytes):
    return ReadCap.from_bytes(read_cap).position_at(MessageBoxIndex.from_bytes(index))


class MeshBackend(Backend):
    """Over a mesh replica, through ``pigeonhole_rns.client.Client``."""

    def __init__(self, client: Client):
        self.client = client

    def write_box(self, write_cap: bytes, index: bytes, plaintext: bytes) -> None:
        pos = _write_position(write_cap, index)
        if plaintext:
            box_id, ciphertext, signature = pos.encrypt(PIGEONHOLE_CTX, pad(plaintext, self.client.box_plaintext_size))
        else:
            box_id, signature = pos.tombstone(PIGEONHOLE_CTX)
            ciphertext = b""
        code = self.client.write_box(box_id, signature, ciphertext)
        if code is None:
            raise TransportError("no replica answered")
        if code == replica_wire.SUCCESS:
            return
        if code in (replica_wire.ALREADY_EXISTS, replica_wire.TOMBSTONE):
            # The replica holds other bytes, or a tombstone where data was written.
            raise BoxExists()
        raise TransportError("replica error %d" % code)

    def read_box(self, read_cap: bytes, index: bytes) -> Outcome:
        pos = _read_position(read_cap, index)
        box_id = pos.box_id(PIGEONHOLE_CTX)
        r = self.client.read_box(box_id)
        if r is None:
            raise TransportError("no replica answered")
        if r.code == replica_wire.NOT_FOUND:
            return Outcome(NOT_FOUND)
        if r.code == replica_wire.TOMBSTONE:
            return Outcome(TOMBSTONE, b"", next_index(index))
        if r.code != replica_wire.SUCCESS:
            raise TransportError("replica error %d" % r.code)
        try:
            plaintext = unpad(pos.open(PIGEONHOLE_CTX, box_id, r.ciphertext or b"", r.signature or b""))
        except Exception as e:
            raise TransportError("box did not open: %s" % e)
        return Outcome(DATA, plaintext, next_index(index))

    def replica_epoch(self) -> int:
        return epoch_now()

    def max_plaintext(self) -> int:
        return self.client.box_plaintext_size


class SimBackend(Backend):
    """An in-memory Pigeonhole with real BACAP: boxes by Box ID, holding
    their plaintext, or None for a tombstone. ``fail_next`` makes the next
    call of a kind fail, once."""

    def __init__(self, max_plaintext: int = 1000, epoch: int = 1):
        self.boxes: Dict[bytes, Optional[bytes]] = {}
        self.epoch = epoch
        self._max = max_plaintext
        self.fail_next: set = set()
        self.writes = 0
        self.reads = 0
        self._mu = threading.Lock()

    def _maybe_fail(self, what: str) -> None:
        if what in self.fail_next:
            self.fail_next.discard(what)
            raise TransportError("injected")

    def write_box(self, write_cap: bytes, index: bytes, plaintext: bytes) -> None:
        with self._mu:
            self._maybe_fail("write")
            self.writes += 1
            box_id = _write_position(write_cap, index).box_id(PIGEONHOLE_CTX)
            cur = self.boxes.get(box_id, b"\0missing")
            new = plaintext if plaintext else None
            if cur == b"\0missing" or cur == new or new is None:
                self.boxes[box_id] = new
                return
            raise BoxExists()

    def read_box(self, read_cap: bytes, index: bytes) -> Outcome:
        with self._mu:
            self._maybe_fail("read")
            self.reads += 1
            box_id = _read_position(read_cap, index).box_id(PIGEONHOLE_CTX)
            if box_id not in self.boxes:
                return Outcome(NOT_FOUND)
            p = self.boxes[box_id]
            if p is None:
                return Outcome(TOMBSTONE, b"", next_index(index))
            return Outcome(DATA, p, next_index(index))

    def replica_epoch(self) -> int:
        return self.epoch

    def max_plaintext(self) -> int:
        return self._max
