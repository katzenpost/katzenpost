"""Acknowledgements: what this member has published, what others have
acknowledged of its stream, and what others have acknowledged of every
stream. An induction holds publishing back. See "Joining" in the group chat
spec.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field

from .wire import Key


class Induction(enum.Enum):
    IDLE = "idle"
    CATCHING_UP = "catching up"
    INDUCTING = "inducting"


@dataclass
class Ledger:
    published: dict[Key, bytes] = field(default_factory=dict)
    """The last index acknowledged of each stream."""
    acked_by: dict[Key, int] = field(default_factory=dict)
    """The ``Idx64`` of the last box of our stream each member has
    acknowledged, after the Sent-box check."""
    heard: dict[Key, dict[Key, int]] = field(default_factory=dict)
    """For each stream, the ``Idx64`` of the last box each other member
    acknowledged of it."""
    induction: Induction = Induction.IDLE
    invitee: tuple[str, bytes] | None = None
    """The name and read cap of the member being inducted."""
    commit: bool = False
    """Commit the induction as soon as catching up is done."""
    starts: dict[Key, bytes] = field(default_factory=dict)
    """Where each stream had been read when the invitation began."""

    @property
    def holding(self) -> bool:
        return self.induction is Induction.INDUCTING

    def owed(self, stream: Key, run: bytes | None) -> bytes | None:
        """The index to acknowledge of ``stream``, the end of the unbroken
        run read, if anything new."""
        if self.holding or run is None or self.published.get(stream) == run:
            return None
        return run

    def publish(self, stream: Key, index: bytes) -> None:
        self.published[stream] = index

    def hear(self, stream: Key, idx64: int, by: Key) -> None:
        self.heard.setdefault(stream, {})[by] = idx64

    def acked(self, member: Key, idx64: int) -> None:
        self.acked_by[member] = max(self.acked_by.get(member, -1), idx64)

    def forget(self, member: Key) -> None:
        self.acked_by.pop(member, None)
        self.heard.pop(member, None)
        for by in self.heard.values():
            by.pop(member, None)
