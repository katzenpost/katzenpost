"""The boxes a member wrote to its own stream: what it may still rewrite,
and what its retention policy lets it forget. See "Sent-box records" and
"Disappearing messages" in the group chat spec.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from .events import Effect, WriteBox, WriteTombstone
from .wire import counter


@dataclass(frozen=True)
class Retention:
    window: int | None = 3
    """Epochs a Sent-box record is kept and backfilled; None keeps it for
    good."""
    discard_acked: bool = True
    """Drop plaintext every member still read has acknowledged."""
    keep_sent: int | None = None
    """Epochs the policy keeps sent content."""
    keep_received: int | None = None
    """Epochs the policy keeps received content."""


@dataclass
class Record:
    index: bytes
    """The box's whole ``MessageBoxIndex``."""
    plaintext: bytes | None
    """None once the plaintext is gone, or if it was never handed over."""
    control: bool
    written: int
    settled: bool = False
    """Written as a tombstone once every member had acknowledged it: there
    is nothing more to write."""


@dataclass
class SentBox:
    records: dict[int, Record] = field(default_factory=dict)
    """By the box's ``Idx64``, which orders the boxes of our stream as we
    wrote them."""
    backfilled: int = -1

    def record(self, index: bytes, plaintext: bytes | None, control: bool, epoch: int) -> None:
        self.records[counter(index)] = Record(index, plaintext, control, epoch)

    def check(self, index: bytes) -> int | None:
        """The Sent-box check: the ``Idx64`` of the box ``index`` names, or
        None if we never wrote it."""
        record = self.records.get(counter(index))
        return counter(index) if record is not None and record.index == index else None

    def check_at(self, idx64: int) -> bool:
        """The Sent-box check for an acknowledgement, which names the box by
        its ``Idx64``."""
        return idx64 in self.records

    def retain(
        self, epoch: int, policy: Retention, everyone_acked: Callable[[int], bool]
    ) -> None:
        window = policy.window
        for idx64 in [
            i for i, r in self.records.items() if window is not None and epoch - r.written > window
        ]:
            del self.records[idx64]
        for idx64, record in self.records.items():
            if (
                not record.control
                and policy.keep_sent is not None
                and epoch - record.written >= policy.keep_sent
            ) or (policy.discard_acked and everyone_acked(idx64)):
                record.plaintext = None

    def backfill(self, epoch: int, everyone_acked: Callable[[int], bool]) -> list[Effect]:
        """Rewrite every record a member has yet to acknowledge, at most
        once per epoch, and write a record every member has acknowledged as
        a tombstone once its plaintext is gone. Nothing when nobody is
        behind."""
        if epoch == self.backfilled:
            return []
        self.backfilled = epoch
        effects: list[Effect] = []
        for idx64, r in sorted(self.records.items()):
            if not everyone_acked(idx64):
                effects.append(
                    WriteBox(r.index, r.plaintext) if r.plaintext is not None
                    else WriteTombstone(r.index)
                )
            elif r.plaintext is None and not r.settled:
                r.settled = True
                effects.append(WriteTombstone(r.index))
        return effects
