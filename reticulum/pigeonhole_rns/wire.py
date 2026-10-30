# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""Query and reply encodings, shared by Reticulum requests and the bridge
socket.

A query is one byte, zero for a read and one for a write, the 32 byte Box
ID, and for a write the 64 byte signature and the ciphertext; a tombstone has
an empty ciphertext. A reply is one result byte, a Pigeonhole replica error
code, and for a found box the signature and ciphertext.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional

READ = 0
WRITE = 1

BOX_ID_SIZE = 32
SIGNATURE_SIZE = 64

# Pigeonhole replica error codes, as in pigeonhole/errors.go.
SUCCESS = 0
NOT_FOUND = 1
INVALID_BOX_ID = 2
INVALID_SIGNATURE = 3
DATABASE_FAILURE = 4
INVALID_PAYLOAD = 5
STORAGE_FULL = 6
INTERNAL_ERROR = 7
INVALID_EPOCH = 8
REPLICATION_FAILED = 9
ALREADY_EXISTS = 10
TOMBSTONE = 11

# Codes that mean the receiver holds the box after a write.
STORED_CODES = frozenset((SUCCESS, ALREADY_EXISTS))


class WireError(ValueError):
    pass


@dataclass(frozen=True)
class Query:
    kind: int
    box_id: bytes
    signature: Optional[bytes] = None
    ciphertext: Optional[bytes] = None


@dataclass(frozen=True)
class Reply:
    code: int
    signature: Optional[bytes] = None
    ciphertext: Optional[bytes] = None


def encode_read(box_id: bytes) -> bytes:
    _check_box_id(box_id)
    return bytes([READ]) + box_id


def encode_write(box_id: bytes, signature: bytes, ciphertext: bytes) -> bytes:
    _check_box_id(box_id)
    if len(signature) != SIGNATURE_SIZE:
        raise WireError("signature must be 64 bytes")
    return bytes([WRITE]) + box_id + signature + ciphertext


def decode_query(data: bytes) -> Query:
    if len(data) < 1 + BOX_ID_SIZE:
        raise WireError("query too short")
    kind = data[0]
    box_id = bytes(data[1 : 1 + BOX_ID_SIZE])
    if kind == READ:
        if len(data) != 1 + BOX_ID_SIZE:
            raise WireError("read carries trailing bytes")
        return Query(READ, box_id)
    if kind == WRITE:
        rest = data[1 + BOX_ID_SIZE :]
        if len(rest) < SIGNATURE_SIZE:
            raise WireError("write lacks a signature")
        return Query(WRITE, box_id, bytes(rest[:SIGNATURE_SIZE]), bytes(rest[SIGNATURE_SIZE:]))
    raise WireError("unknown query type %d" % kind)


def encode_reply(code: int, signature: Optional[bytes] = None, ciphertext: Optional[bytes] = None) -> bytes:
    out = bytes([code])
    if code == SUCCESS and signature is not None:
        out += signature + (ciphertext or b"")
    return out


def decode_reply(data: bytes) -> Reply:
    if len(data) < 1:
        raise WireError("empty reply")
    code = data[0]
    if code == SUCCESS and len(data) > 1:
        rest = data[1:]
        if len(rest) < SIGNATURE_SIZE:
            raise WireError("found reply lacks a signature")
        return Reply(code, bytes(rest[:SIGNATURE_SIZE]), bytes(rest[SIGNATURE_SIZE:]))
    return Reply(code)


# The bridge socket carries each message as a big endian u32 length prefix
# followed by the payload.

MAX_FRAME = 1 << 20


def write_frame(sock, payload: bytes) -> None:
    sock.sendall(struct.pack(">I", len(payload)) + payload)


def read_frame(sock) -> bytes:
    hdr = _read_exact(sock, 4)
    (n,) = struct.unpack(">I", hdr)
    if n == 0 or n > MAX_FRAME:
        raise WireError("frame length %d out of range" % n)
    return _read_exact(sock, n)


def _read_exact(sock, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError("socket closed")
        buf += chunk
    return bytes(buf)


def _check_box_id(box_id: bytes) -> None:
    if len(box_id) != BOX_ID_SIZE:
        raise WireError("box id must be 32 bytes")
