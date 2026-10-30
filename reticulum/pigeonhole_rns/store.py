# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""SQLite store: boxes, the forward queue and the acknowledgements that let a
stand-in drop its copy, in one file so that storing a box and enqueueing its
forwards is one commit."""

from __future__ import annotations

import sqlite3
import threading
from dataclasses import dataclass
from typing import Iterable, List, Optional, Set, Tuple

from . import wire

SCHEMA = """
CREATE TABLE IF NOT EXISTS boxes (
    box_id    BLOB PRIMARY KEY,
    epoch     INTEGER NOT NULL,
    signature BLOB NOT NULL,
    payload   BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS boxes_epoch ON boxes(epoch);
CREATE TABLE IF NOT EXISTS acks (
    box_id  BLOB NOT NULL,
    dst     BLOB NOT NULL,
    PRIMARY KEY (box_id, dst)
);
CREATE TABLE IF NOT EXISTS queue (
    box_id   BLOB NOT NULL,
    dst      BLOB NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_try REAL NOT NULL,
    PRIMARY KEY (box_id, dst)
);
"""


@dataclass(frozen=True)
class Box:
    box_id: bytes
    epoch: int
    signature: bytes
    payload: bytes

    @property
    def is_tombstone(self) -> bool:
        return len(self.payload) == 0


class Store:
    def __init__(self, path: str):
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._lock = threading.RLock()
        with self._lock:
            self._db.execute("PRAGMA journal_mode=WAL")
            self._db.execute("PRAGMA synchronous=FULL")
            self._db.executescript(SCHEMA)

    def close(self) -> None:
        with self._lock:
            self._db.close()

    # ---- boxes ----

    def get(self, box_id: bytes) -> Optional[Box]:
        with self._lock:
            row = self._db.execute(
                "SELECT epoch, signature, payload FROM boxes WHERE box_id = ?", (box_id,)
            ).fetchone()
        if row is None:
            return None
        return Box(box_id, row[0], bytes(row[1]), bytes(row[2]))

    def put(self, box_id: bytes, signature: bytes, payload: bytes, epoch: int, dsts: Iterable[bytes] = ()) -> int:
        """Stores a box and enqueues forwards to dsts in one transaction.

        Write once: the same bytes again is success, different bytes is
        ALREADY_EXISTS, a tombstone replaces whatever is there, and a box
        never replaces a tombstone. Returns a wire code."""
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                row = self._db.execute(
                    "SELECT signature, payload FROM boxes WHERE box_id = ?", (box_id,)
                ).fetchone()
                if row is not None:
                    cur_sig, cur_payload = bytes(row[0]), bytes(row[1])
                    if len(cur_payload) == 0:
                        code = wire.SUCCESS if len(payload) == 0 else wire.ALREADY_EXISTS
                        self._db.execute("COMMIT")
                        return code
                    if len(payload) != 0:
                        code = wire.SUCCESS if (cur_sig == signature and cur_payload == payload) else wire.ALREADY_EXISTS
                        self._db.execute("COMMIT")
                        return code
                    # A tombstone replaces the box and the acks it had collected.
                    self._db.execute("DELETE FROM acks WHERE box_id = ?", (box_id,))
                self._db.execute(
                    "INSERT OR REPLACE INTO boxes (box_id, epoch, signature, payload) VALUES (?, ?, ?, ?)",
                    (box_id, epoch, signature, payload),
                )
                for dst in dsts:
                    self._db.execute(
                        "INSERT OR IGNORE INTO queue (box_id, dst, attempts, next_try) VALUES (?, ?, 0, 0)",
                        (box_id, dst),
                    )
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise
        return wire.SUCCESS

    def drop(self, box_id: bytes) -> None:
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            self._db.execute("DELETE FROM boxes WHERE box_id = ? AND length(payload) > 0", (box_id,))
            self._db.execute("DELETE FROM acks WHERE box_id = ?", (box_id,))
            self._db.execute("COMMIT")

    def box_ids(self) -> List[bytes]:
        with self._lock:
            return [bytes(r[0]) for r in self._db.execute("SELECT box_id FROM boxes")]

    def sweep(self, keep_epochs: Iterable[int]) -> int:
        keep = list(keep_epochs)
        marks = ",".join("?" for _ in keep)
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            cur = self._db.execute("DELETE FROM boxes WHERE epoch NOT IN (%s)" % marks, keep)
            self._db.execute("DELETE FROM acks WHERE box_id NOT IN (SELECT box_id FROM boxes)")
            self._db.execute("DELETE FROM queue WHERE box_id NOT IN (SELECT box_id FROM boxes)")
            self._db.execute("COMMIT")
            return cur.rowcount

    # ---- forward queue and acknowledgements ----

    def enqueue(self, box_id: bytes, dst: bytes) -> None:
        with self._lock:
            self._db.execute(
                "INSERT OR IGNORE INTO queue (box_id, dst, attempts, next_try) VALUES (?, ?, 0, 0)",
                (box_id, dst),
            )

    def due(self, now: float) -> List[Tuple[bytes, bytes, int]]:
        with self._lock:
            rows = self._db.execute(
                "SELECT box_id, dst, attempts FROM queue WHERE next_try <= ? ORDER BY next_try", (now,)
            ).fetchall()
        return [(bytes(r[0]), bytes(r[1]), r[2]) for r in rows]

    def queued(self, box_id: bytes) -> Set[bytes]:
        with self._lock:
            rows = self._db.execute("SELECT dst FROM queue WHERE box_id = ?", (box_id,)).fetchall()
        return {bytes(r[0]) for r in rows}

    def ack(self, box_id: bytes, dst: bytes) -> None:
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            self._db.execute("DELETE FROM queue WHERE box_id = ? AND dst = ?", (box_id, dst))
            self._db.execute("INSERT OR IGNORE INTO acks (box_id, dst) VALUES (?, ?)", (box_id, dst))
            self._db.execute("COMMIT")

    def acked(self, box_id: bytes) -> Set[bytes]:
        with self._lock:
            rows = self._db.execute("SELECT dst FROM acks WHERE box_id = ?", (box_id,)).fetchall()
        return {bytes(r[0]) for r in rows}

    def backoff(self, box_id: bytes, dst: bytes, next_try: float) -> None:
        with self._lock:
            self._db.execute(
                "UPDATE queue SET attempts = attempts + 1, next_try = ? WHERE box_id = ? AND dst = ?",
                (next_try, box_id, dst),
            )

    def forget(self, box_id: bytes, dst: bytes) -> None:
        with self._lock:
            self._db.execute("DELETE FROM queue WHERE box_id = ? AND dst = ?", (box_id, dst))
