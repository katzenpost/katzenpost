# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""The chat client: the engine, its state on disk, and its work carried out
over a backend. ``Client`` runs the engine under one lock; actions run on
worker threads and their outcomes are fed back. ``SyncClient`` is the same
client with a virtual clock, carrying every action out inline in due
order, for tests."""

from __future__ import annotations

import heapq
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Callable, List, Optional

from . import backend as be
from . import engine as eng
from .member.events import Walk
from .member.walk import walk
from .store import Store

RETRY_MS = 5000


@dataclass
class Performed:
    """What came of an action: an input for the engine now, the action to
    try again later, or an input to hand the engine later."""

    input: object = None
    retry: object = None
    after_ms: int = 0


def _describe(a) -> str:
    return {
        eng.DoCreate: "new stream",
        eng.DoMint: "mint a voucher",
        eng.DoAwaitReply: "wait for the voucher's reply",
        eng.DoReadVoucher: "read a voucher's box 0",
        eng.DoSeal: "seal the reply to a voucher",
        eng.DoPublish: "publish the reply to a voucher",
    }.get(type(a), type(a).__name__)


def _chat_of(a) -> str:
    return getattr(a, "chat", "")


class Client:
    """Methods may be called from any thread. ``on_change`` is called after
    each step with the engine's Changes."""

    def __init__(
        self,
        state_dir: str,
        name: str,
        backend: be.Backend,
        epoch_poll_s: float = 60.0,
        on_change: Optional[Callable[[eng.Changes], None]] = None,
        workers: int = 8,
    ):
        self.backend = backend
        self.store = Store(state_dir)
        self.state = self.store.load(name)
        self.engine = eng.Engine(self.state, backend.max_plaintext())
        self.on_change = on_change
        self._lock = threading.RLock()
        self._closed = False
        self._epoch_poll_s = epoch_poll_s
        self._pool: Optional[ThreadPoolExecutor] = ThreadPoolExecutor(max_workers=workers) if workers else None
        self._timers: List[threading.Timer] = []
        self._epoch_thread: Optional[threading.Thread] = None
        self._stop = threading.Event()

    # ---- time ----

    def now_ms(self) -> int:
        return int(time.time() * 1000)

    def sleep(self, ms: int) -> None:
        self._stop.wait(ms / 1000.0)

    # ---- running ----

    def start(self) -> None:
        with self._lock:
            r = self.engine.resume(self.now_ms())
            self.store.commit(self.state, r)
        self._dispatch(r)
        if self._epoch_poll_s > 0:
            self._epoch_thread = threading.Thread(target=self._watch_epoch, daemon=True)
            self._epoch_thread.start()

    def _watch_epoch(self) -> None:
        while not self._stop.is_set():
            try:
                n = self.backend.replica_epoch()
                self.feed(eng.Epoch(n))
            except Exception:
                pass
            self._stop.wait(self._epoch_poll_s)

    def feed(self, inp) -> None:
        """One input: step the engine, save, then start the work it asks for."""
        if self._closed:
            return
        with self._lock:
            r = self.engine.step(self.now_ms(), inp)
            self.store.commit(self.state, r)
            changes = r.changes
        if self.on_change is not None and not changes.empty():
            self.on_change(changes)
        self._dispatch(r)

    def _dispatch(self, r: eng.Result) -> None:
        for a in r.actions:
            self._submit(a, 0)

    def _submit(self, a, after_ms: int) -> None:
        if self._closed:
            return
        if after_ms > 0:
            t = threading.Timer(after_ms / 1000.0, self._run, (a,))
            t.daemon = True
            with self._lock:
                self._timers = [x for x in self._timers if x.is_alive()] + [t]
            t.start()
        elif self._pool is not None:
            self._pool.submit(self._run, a)
        else:
            self._run(a)

    def _run(self, a) -> None:
        if self._closed:
            return
        with self._lock:
            if not self.state.wanted(a):
                return
        p = self.perform(a)
        if p.input is not None:
            if p.after_ms > 0:
                t = threading.Timer(p.after_ms / 1000.0, self.feed, (p.input,))
                t.daemon = True
                t.start()
                with self._lock:
                    self._timers.append(t)
            else:
                self.feed(p.input)
        if p.retry is not None:
            self._submit(p.retry, p.after_ms)

    def close(self) -> None:
        self._closed = True
        self._stop.set()
        with self._lock:
            timers = list(self._timers)
        for t in timers:
            t.cancel()
        if self._pool is not None:
            self._pool.shutdown(wait=True, cancel_futures=True)
        self.store.close()

    # ---- carrying out actions ----

    def _publish(self, write_cap: bytes, index: bytes, box: bytes) -> None:
        """Write a box until it is written."""
        while True:
            try:
                self.backend.write_box(write_cap, index, box)
                return
            except be.BoxExists:
                raise
            except be.TransportError:
                if self._closed:
                    raise
                self.sleep(RETRY_MS)

    def perform(self, a) -> Performed:
        """Carry out one action. It never waits to try again; the caller
        does."""
        try:
            return self._perform(a)
        except (be.TransportError, be.BoxExists, Exception) as e:
            if isinstance(a, (eng.DoRead, eng.DoScanRead, eng.DoWrite, eng.DoDerive, eng.DoWalk)):
                return Performed(retry=a, after_ms=RETRY_MS)
            if isinstance(a, eng.DoDelete):
                return Performed()
            return Performed(input=eng.Failed(_chat_of(a), "%s failed: %s" % (_describe(a), e)))

    def _perform(self, a) -> Performed:
        b = self.backend
        if isinstance(a, eng.DoCreate):
            return Performed(eng.Created(a.chat, a.joining, b.new_keypair()))
        if isinstance(a, eng.DoWrite):
            try:
                b.write_box(a.write_cap, a.index, a.box)
            except be.BoxExists:
                return Performed(eng.Refused(a.chat, a.job))
            return Performed(eng.Wrote(a.chat, a.job, a.index, be.next_index(a.index)))
        if isinstance(a, eng.DoRead):
            return Performed(eng.Read(a.chat, a.stream, a.index, b.read_box(a.read_cap, a.index)))
        if isinstance(a, eng.DoWake):
            return Performed(eng.Wake(a.chat, a.stream), after_ms=a.ms)
        if isinstance(a, eng.DoScanRead):
            return Performed(eng.ScanRead(a.chat, a.stream, a.index, b.read_box(a.read_cap, a.index)))
        if isinstance(a, eng.DoWalk):
            w = walk(Walk(a.stream, a.start, tuple(a.targets), a.keep), 1 << 62)
            return Performed(eng.Walked(a.chat, a.stream, w.target, tuple(w.skipped), w.steps))
        if isinstance(a, eng.DoDerive):
            return Performed(eng.Derived(a.chat, a.stream, be.derive(a.start, a.count)))
        if isinstance(a, eng.DoMint):
            m = b.voucher_mint(a.write_cap, a.name)
            box0 = m.write_cap[len(m.write_cap) - 104 :]
            self._publish(m.write_cap, box0, m.payload)
            return Performed(eng.MintedIn(a.chat, m, be.next_index(box0)))
        if isinstance(a, eng.DoAwaitReply):
            # A read that fails is tried again, as a box not yet written is.
            try:
                r = b.read_box(a.voucher_read_cap, a.box1)
            except be.TransportError:
                return Performed(retry=a, after_ms=RETRY_MS)
            if r.kind == eng.NOT_FOUND:
                return Performed(retry=a, after_ms=RETRY_MS)
            if r.kind == eng.TOMBSTONE:
                return Performed(eng.Failed(a.chat, "the voucher's reply was withdrawn"))
            return Performed(eng.OpenedIn(a.chat, b.voucher_open(a.secret_key, r.plaintext, a.write_cap)))
        if isinstance(a, eng.DoReadVoucher):
            wc, rc = b.voucher_derive_stream(a.voucher)
            box0 = rc[32:]
            try:
                r = b.read_box(rc, box0)
            except be.TransportError:
                return Performed(retry=a, after_ms=RETRY_MS)
            if r.kind == eng.NOT_FOUND:
                return Performed(retry=a, after_ms=RETRY_MS)
            if r.kind == eng.TOMBSTONE:
                return Performed(eng.Failed(a.chat, "that voucher was withdrawn"))
            return Performed(eng.JoinerPayload(a.chat, a.voucher, wc, r.plaintext, be.next_index(box0)))
        if isinstance(a, eng.DoSeal):
            return Performed(eng.SealedReply(a.chat, b.voucher_induct(a.voucher, a.payload, a.who_reply)))
        if isinstance(a, eng.DoPublish):
            self._publish(a.voucher_write_cap, a.box1, a.reply)
            return Performed(eng.Published(a.chat))
        if isinstance(a, eng.DoDelete):
            self.store.remove(a.file)
            return Performed()
        raise ValueError("unknown action %r" % (a,))

    # ---- what an app asks ----

    def chat_id(self, name: str) -> Optional[str]:
        with self._lock:
            c = self.state.chat_named(name)
            return c.id if c else None

    def chats(self) -> List[eng.Chat]:
        with self._lock:
            return list(self.state.chats)

    def lines(self, chat: str) -> List[eng.Line]:
        with self._lock:
            c = self.state.chat(chat)
            return list(c.log) if c else []

    def members(self, chat: str) -> List[tuple]:
        """(key, name) of each member read, and ourselves first."""
        with self._lock:
            c = self.state.chat(chat)
            if c is None or c.group is None:
                return []
            out = [(c.group.me, self.state.me)]
            for k in c.group.readers:
                out.append((k, c.names.get(k, "?")))
            return out

    def plain(self, chat: str, line: eng.Line) -> str:
        """A line in words: who said what, or a notice."""
        if line.notice is not None:
            return "— " + eng.plain(line.notice)
        with self._lock:
            c = self.state.chat(chat)
            who = self.state.me if c is not None and c.group is not None and line.sender == c.group.me else (c.names.get(line.sender, "?") if c else "?")
        return "%s: %s" % (who, line.text)


class SyncClient(Client):
    """The client with a virtual clock: nothing runs until ``run`` is
    called, which carries out every action in due order and returns once
    nothing is due within ``for_ms``."""

    def __init__(self, state_dir: str, name: str, backend: be.Backend, clock=None, on_change=None):
        super().__init__(state_dir, name, backend, epoch_poll_s=0, on_change=on_change, workers=0)
        self._clock = clock if clock is not None else [0]
        self._due: list = []
        self._seq = 0

    def now_ms(self) -> int:
        return self._clock[0]

    def sleep(self, ms: int) -> None:
        self._clock[0] += ms

    def _submit(self, a, after_ms: int) -> None:
        self._seq += 1
        heapq.heappush(self._due, (self._clock[0] + after_ms, self._seq, "action", a))

    def _run(self, a) -> None:
        if not self.state.wanted(a):
            return
        p = self.perform(a)
        if p.input is not None:
            if p.after_ms > 0:
                self._seq += 1
                heapq.heappush(self._due, (self._clock[0] + p.after_ms, self._seq, "input", p.input))
            else:
                self.feed(p.input)
        if p.retry is not None:
            self._submit(p.retry, p.after_ms)

    def run(self, for_ms: int = 0) -> None:
        """Carry out what is due, advancing the clock to each item, until
        nothing is due before now + for_ms."""
        end = self._clock[0] + for_ms
        while self._due and self._due[0][0] <= end:
            when, _, kind, x = heapq.heappop(self._due)
            self._clock[0] = max(self._clock[0], when)
            if kind == "action":
                self._run(x)
            else:
                self.feed(x)
        self._clock[0] = max(self._clock[0], end)

    def quiet(self) -> bool:
        return not self._due
