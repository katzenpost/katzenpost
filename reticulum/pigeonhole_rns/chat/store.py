# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""The client's state on disk: SQLite for the chats and their lines, and
files under the state directory for what a step asks to keep. A step's
changes are saved, synced, before any of the work it asks for starts."""

from __future__ import annotations

import os
import sqlite3
from typing import Optional

import cbor2

from . import engine
from .member import state as member_state

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS chats (id TEXT PRIMARY KEY, pos INTEGER NOT NULL, data BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS lines (chat TEXT NOT NULL, id INTEGER NOT NULL, data BLOB NOT NULL, PRIMARY KEY (chat, id));
"""


def _opt(b: Optional[bytes]) -> Optional[bytes]:
    return None if b is None else bytes(b)


def encode_chat(c: engine.Chat) -> bytes:
    return cbor2.dumps(
        {
            "id": c.id,
            "name": c.name,
            "write_cap": c.write_cap,
            "next_write": c.next_write,
            "group": member_state.dump(c.group) if c.group is not None else None,
            "cursors": [[k, v] for k, v in c.cursors.items()],
            "names": [[k, v] for k, v in c.names.items()],
            "jobs": [[j.id, j.token, j.index, j.box, j.line] for j in c.jobs],
            "joining": None if c.joining is None else [c.joining.code, c.joining.secret_key, c.joining.voucher_read_cap, c.joining.box1],
            "inducting": None
            if c.inducting is None
            else [
                c.inducting.voucher,
                c.inducting.payload,
                c.inducting.voucher_write_cap,
                c.inducting.box1,
                c.inducting.sealing,
                None if c.inducting.sealed is None else [c.inducting.sealed.name, c.inducting.sealed.mutated_read_cap, c.inducting.sealed.reply],
            ],
            "next_id": c.next_id,
        }
    )


def decode_chat(data: bytes) -> engine.Chat:
    d = cbor2.loads(data)
    c = engine.Chat(d["id"], d["name"], d["write_cap"], d["next_write"])
    if d["group"] is not None:
        c.group = member_state.load(d["group"], codec=engine.wire.Codec())
        c.group.pool, c.group.deriving = [], True
    c.cursors = {k: v for k, v in d["cursors"]}
    c.names = {k: v for k, v in d["names"]}
    c.jobs = [engine.Job(*j) for j in d["jobs"]]
    if d["joining"] is not None:
        c.joining = engine.Joining(*d["joining"])
    if d["inducting"] is not None:
        v, p, wc, b1, sealing, sealed = d["inducting"]
        c.inducting = engine.Inducting(v, p, wc, b1, sealing, None if sealed is None else engine.Sealed(*sealed))
    c.next_id = d["next_id"]
    return c


def encode_line(l: engine.Line) -> bytes:
    return cbor2.dumps([l.id, l.sender, l.index, l.text, None if l.notice is None else [l.notice.kind, list(l.notice.args)], l.status, l.idx64, l.time])


def decode_line(data: bytes) -> engine.Line:
    id, sender, index, text, notice, status, idx64, time = cbor2.loads(data)
    return engine.Line(id, sender, index, text, None if notice is None else engine.Notice(notice[0], tuple(notice[1])), status, idx64, time)


class Store:
    def __init__(self, state_dir: str):
        os.makedirs(state_dir, exist_ok=True)
        self.dir = state_dir
        self.db = sqlite3.connect(os.path.join(state_dir, "chat.sqlite"), check_same_thread=False, isolation_level=None)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.executescript(SCHEMA)

    def load(self, me: str) -> engine.State:
        """The state, named ``me`` when it has no name yet."""
        row = self.db.execute("SELECT value FROM meta WHERE key='me'").fetchone()
        if row is None:
            self.db.execute("INSERT INTO meta VALUES ('me', ?)", (me.encode(),))
        else:
            me = bytes(row[0]).decode()
        s = engine.State(me)
        for (data,) in self.db.execute("SELECT data FROM chats ORDER BY pos"):
            s.chats.append(decode_chat(data))
        for c in s.chats:
            c.log = [decode_line(d) for (d,) in self.db.execute("SELECT data FROM lines WHERE chat=? ORDER BY id", (c.id,))]
        return s

    def path(self, file: str) -> str:
        return os.path.join(self.dir, file)

    def commit(self, s: engine.State, r: engine.Result) -> None:
        """Keep the files, then save what changed, in one transaction."""
        for f in r.files:
            p = self.path(f.file)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p + ".tmp", "wb") as fh:
                fh.write(f.data)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(p + ".tmp", p)
        ch = r.changes
        if ch.empty():
            return
        self.db.execute("BEGIN IMMEDIATE")
        try:
            for id in ch.removed:
                self.db.execute("DELETE FROM chats WHERE id=?", (id,))
                self.db.execute("DELETE FROM lines WHERE chat=?", (id,))
            for id in ch.chats:
                c = s.chat(id)
                if c is None:
                    continue
                self.db.execute("INSERT OR REPLACE INTO chats VALUES (?, ?, ?)", (id, s.chats.index(c), encode_chat(c)))
            for id, dropped in ch.dropped.items():
                for lid in dropped:
                    self.db.execute("DELETE FROM lines WHERE chat=? AND id=?", (id, lid))
            for id, lines in ch.lines.items():
                c = s.chat(id)
                if c is None:
                    continue
                by_id = {l.id: l for l in c.log}
                for lid in lines:
                    if lid in by_id:
                        self.db.execute("INSERT OR REPLACE INTO lines VALUES (?, ?, ?)", (id, lid, encode_line(by_id[lid])))
            self.db.execute("COMMIT")
        except Exception:
            self.db.execute("ROLLBACK")
            raise

    def remove(self, file: str) -> None:
        try:
            os.remove(self.path(file))
        except FileNotFoundError:
            pass

    def close(self) -> None:
        self.db.close()
