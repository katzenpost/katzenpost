# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""The mesh side of a bridge: a client of the Katzenpost replica's bridge
socket on the same host, speaking the same read and write messages."""

from __future__ import annotations

import socket
import threading
from typing import Optional

from . import wire


class BridgeSocket:
    def __init__(self, path: str, timeout: float = 120.0):
        self.path = path
        self.timeout = timeout
        self._sock: Optional[socket.socket] = None
        self._lock = threading.Lock()

    def _connect(self) -> socket.socket:
        if self._sock is None:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect(self.path)
            self._sock = s
        return self._sock

    def _exchange(self, payload: bytes) -> Optional[bytes]:
        with self._lock:
            try:
                s = self._connect()
                wire.write_frame(s, payload)
                return wire.read_frame(s)
            except (OSError, EOFError, wire.WireError):
                if self._sock is not None:
                    try:
                        self._sock.close()
                    finally:
                        self._sock = None
                return None

    def write(self, box_id: bytes, signature: bytes, ciphertext: bytes) -> Optional[int]:
        raw = self._exchange(wire.encode_write(box_id, signature, ciphertext))
        return None if raw is None else raw[0]

    def read(self, box_id: bytes) -> Optional[wire.Reply]:
        raw = self._exchange(wire.encode_read(box_id))
        if raw is None:
            return None
        try:
            return wire.decode_reply(raw)
        except wire.WireError:
            return None

    def close(self) -> None:
        with self._lock:
            if self._sock is not None:
                self._sock.close()
                self._sock = None
