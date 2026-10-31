"""Reading one member's stream: in order, a box at a time, with the boxes a
scan stepped past kept for rechecking, and a scan that can jump ahead to a
box another member has acknowledged. What a reader acknowledges is the end
of the unbroken run it has read. See "Rewrite and scan" in the group chat
spec.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field

from .events import Effect, Missing, ReadBox, Walk
from .wire import Key, counter


class Mode(enum.Enum):
    IDLE = "idle"
    READING = "reading"
    SCANNING = "scanning"


@dataclass
class Reader:
    stream: Key
    read_cap: bytes
    next: bytes
    """The index of the next box to read."""
    last: bytes | None = None
    """The last box read in order, data or tombstone."""
    passed: int = 0
    """How many boxes this reader has passed: its own count, by which it
    orders the boxes it keeps and measures how far behind it one is."""
    kept: list[tuple[bytes, int, bytes | None]] = field(default_factory=list)
    """Boxes a scan stepped past without reading, oldest first: each with
    the count it was passed at and the box before it, for rechecking."""
    lost: tuple[int, bytes | None] | None = None
    """The first box passed unread and no longer kept, as a kept box is: it
    will never be read, so acknowledgements stop before it for good."""
    mode: Mode = Mode.IDLE
    tried: list[int] = field(default_factory=list)
    """The ``Idx64`` of each acknowledged box a scan has already looked
    for."""

    def read(self) -> list[Effect]:
        if self.mode is not Mode.IDLE:
            return []
        self.mode = Mode.READING
        return [ReadBox(self.stream, self.read_cap, self.next)]

    def ahead(self, heard: list[int]) -> list[int]:
        """Acknowledged boxes a scan has not looked for yet."""
        here = counter(self.next)
        return [h for h in heard if h != here and h not in self.tried]

    def scan(self, heard: list[int], window: int) -> list[Effect]:
        """Recheck what was kept, then look for acknowledged boxes ahead,
        or probe forward from here."""
        self.mode = Mode.SCANNING
        effects: list[Effect] = [
            ReadBox(self.stream, self.read_cap, index, recheck=True) for index, _, _ in self.kept
        ]
        targets = self.ahead(heard)
        if targets:
            self.tried += targets
            return effects + [Walk(self.stream, self.next, tuple(targets), window)]
        return effects + [ReadBox(self.stream, self.read_cap, self.next)]

    @property
    def run(self) -> bytes | None:
        """The end of the unbroken run read: how far this stream may be
        acknowledged."""
        gaps = [(at, before) for _, at, before in self.kept]
        if self.lost is not None:
            gaps.append(self.lost)
        if not gaps:
            return self.last
        return min(gaps, key=lambda gap: gap[0])[1]

    def walked(
        self, target: bytes | None, skipped: tuple[bytes, ...], steps: int, window: int
    ) -> list[Effect]:
        if target is not None:
            start = self.passed + steps - len(skipped)
            if start > self.passed:
                self._lose(self.passed, self.last)
            before = self.last
            for i, index in enumerate(skipped):
                self.kept.append((index, start + i, before))
                before = index
            self.passed += steps
            self.next = target
            self._forget(window)
        return [ReadBox(self.stream, self.read_cap, self.next)]

    def _lose(self, at: int, before: bytes | None) -> None:
        if self.lost is None or at < self.lost[0]:
            self.lost = (at, before)

    def _forget(self, window: int) -> None:
        for _, at, before in self.kept:
            if at < self.passed - window:
                self._lose(at, before)
        self.kept = [box for box in self.kept if box[1] >= self.passed - window]

    def found(
        self, index: bytes, result: bytes | Missing, next_index: bytes | None, window: int
    ) -> tuple[bytes | None, list[Effect]]:
        """Take one box read. Returns its plaintext if it is new data to
        ingest, and what to read next."""
        kept = [box for box in self.kept if box[0] == index]
        if kept:
            if result is not Missing.NOT_FOUND:
                self.kept.remove(kept[0])
            return (result if isinstance(result, bytes) else None), []
        if index != self.next or self.mode is Mode.IDLE:
            return None, []
        if result is Missing.NOT_FOUND or next_index is None:
            self.mode = Mode.IDLE
            return None, []
        self.last = index
        self.next = next_index
        self.passed += 1
        self._forget(window)
        effects: list[Effect] = [ReadBox(self.stream, self.read_cap, self.next)]
        return (result if isinstance(result, bytes) else None), effects
