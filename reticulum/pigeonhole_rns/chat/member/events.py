"""What a driver tells the group state machine, and what the machine asks
the driver to do. Effects map onto thin client calls: the machine never
derives a BACAP index, encrypts, or touches the network itself.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import TypeAlias

from .wire import Key


class Missing(enum.Enum):
    TOMBSTONE = "tombstone"
    NOT_FOUND = "not found"


# Events.


@dataclass(frozen=True)
class Send:
    content: bytes


@dataclass(frozen=True)
class Read:
    stream: Key


@dataclass(frozen=True)
class Scan:
    stream: Key


@dataclass(frozen=True)
class BoxRead:
    """The result of :class:`ReadBox`. ``next_index`` is the index after
    ``index``, which a thin client read returns alongside the box."""

    stream: Key
    index: bytes
    result: bytes | Missing
    next_index: bytes | None = None


@dataclass(frozen=True)
class IndexesDerived:
    """The result of :class:`DeriveIndexes`."""

    stream: Key
    indexes: tuple[bytes, ...]


@dataclass(frozen=True)
class Walked:
    """The result of :class:`Walk`: the furthest target met, or None, how
    many steps it took to meet it, and the indexes stepped past on the way,
    the last ``keep`` of them."""

    stream: Key
    target: bytes | None
    skipped: tuple[bytes, ...]
    steps: int = 0


@dataclass(frozen=True)
class Invite:
    """An induction begins: catch up, then hold acknowledgements back."""

    name: str
    read_cap: bytes


@dataclass(frozen=True)
class Introduce:
    """Commit an induction, starting one first if none is under way."""

    name: str
    read_cap: bytes


@dataclass(frozen=True)
class Remove:
    member: Key


@dataclass(frozen=True)
class EpochChanged:
    epoch: int


Event: TypeAlias = (
    Send | Read | Scan | BoxRead | IndexesDerived | Walked | Invite | Introduce
    | Remove | EpochChanged
)


# Effects.


@dataclass(frozen=True)
class WriteBox:
    index: bytes
    plaintext: bytes


@dataclass(frozen=True)
class WriteTombstone:
    index: bytes


@dataclass(frozen=True)
class ReadBox:
    stream: Key
    read_cap: bytes
    index: bytes
    recheck: bool = False


@dataclass(frozen=True)
class DeriveIndexes:
    """The ``count`` indexes that follow ``start`` on our own stream."""

    stream: Key
    start: bytes
    count: int


@dataclass(frozen=True)
class Walk:
    """Step ``stream`` forward from ``start`` to the furthest box whose
    ``Idx64`` is one of ``targets``, by BACAP's derivation."""

    stream: Key
    start: bytes
    targets: tuple[int, ...]
    keep: int


@dataclass(frozen=True)
class Deliver:
    """Content read from the box ``index`` of ``sender``'s stream, for the
    user."""

    sender: Key
    index: bytes
    content: bytes


@dataclass(frozen=True)
class Expire:
    """The retention policy deletes content previously delivered."""

    sender: Key
    index: bytes


@dataclass(frozen=True)
class SendJoinReply:
    to: bytes
    reply: "JoinReply"


Effect: TypeAlias = (
    WriteBox | WriteTombstone | ReadBox | DeriveIndexes | Walk | Deliver | Expire
    | SendJoinReply
)


@dataclass(frozen=True)
class JoinReply:
    """What an introducer hands a new member, before it knows the new
    member's read cap or where its ``Introduction`` will land. Members are
    named by their place in ``members``, which is the introducer's roster;
    the new member's own place is ``newcomer``, the next one.

    ``members``: each member's read cap and start index, or None for a slot
    the introducer cannot or will not fill. ``rosters``: each member's
    roster as the introducer knows it, as (index, place); None when
    unknown. ``introductions``: (introducer place, ``MessageBoxIndex``,
    member place).
    """

    members: tuple[tuple[bytes, bytes] | None, ...]
    rosters: tuple[tuple[tuple[int, int | None], ...] | None, ...]
    introductions: tuple[tuple[int, bytes, int], ...]
    introducer: int
    """The introducer's place."""
    newcomer: int
    """The new member's place."""
