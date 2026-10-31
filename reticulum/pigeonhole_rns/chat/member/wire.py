"""What a group chat message says to the protocol, and the hand-made
encodings of its control fields. See "Opportunistic acknowledgements and
backfill" in the group chat spec.

A box is named by its ``MessageBoxIndex``: a BACAP value, compared for
equality and moved forward only by BACAP. An acknowledgement names a box by
its ``Idx64`` alone (:func:`counter`), which the stream's read cap turns
back into the whole index.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Protocol

import cbor2
from hpqc.bacap import MessageBoxIndex

from . import ack_codec

Key = bytes
"""A member's identity: the public key its read cap begins with."""

KEY_SIZE = 32
INDEX_SIZE = 104
ROSTER_MAX = 256
"""The most entries a roster holds: roster indexes are one byte."""
PREFIX_SIZE = 8
"""How much of a member's key a ``Numbers`` field names it by."""


def key_of(read_cap: bytes) -> Key:
    return read_cap[:KEY_SIZE]


def prefix_of(key: Key) -> bytes:
    return key[:PREFIX_SIZE]


def counter(index: bytes) -> int:
    """The BACAP ``Idx64`` of the box ``index`` names: what an
    acknowledgement carries."""
    return MessageBoxIndex.from_bytes(index).idx_64


@dataclass(frozen=True)
class IntroRef:
    """An ``Introduction``: its introducer's roster index in the sender's
    roster, and its ``MessageBoxIndex``."""

    introducer: int
    index: bytes


@dataclass(frozen=True)
class Introduction:
    name: str
    read_cap: bytes


Numbers = tuple[tuple[int, bytes | None], ...]
"""Roster indexes assigned, consecutive, each with the key prefix of the
member assigned it; None for the member the message's own ``Introduction``
introduces."""


@dataclass(frozen=True)
class Message:
    """``content`` is opaque here. A message carries content or control,
    never both."""

    content: bytes | None = None
    introduction: Introduction | None = None
    numbers: Numbers = ()
    introduced_at: IntroRef | None = None
    acks: Mapping[int, int] = field(default_factory=dict)
    """Roster index to the ``Idx64`` of the box acknowledged."""

    @property
    def control(self) -> bool:
        return bool(
            self.introduction or self.numbers or self.introduced_at
        )


def encode_numbers(numbers: Numbers) -> bytes:
    """The first index assigned, then the key prefix of each member, one per
    consecutive index; a lone byte for the member an ``Introduction``
    introduces.

    >>> numbers = ((3, b"erin1234"), (4, b"dave5678"))
    >>> len(encode_numbers(numbers)), decode_numbers(encode_numbers(numbers)) == numbers
    (17, True)
    >>> encode_numbers(((4, None),))
    b'\\x04'
    """
    if len(numbers) == 1 and numbers[0][1] is None:
        return bytes([numbers[0][0]])
    if not numbers:
        return b""
    return bytes([numbers[0][0]]) + b"".join(prefix for _, prefix in numbers if prefix)


def decode_numbers(field: bytes) -> Numbers:
    """Empty when the field is malformed.

    >>> decode_numbers(b"\\x04")
    ((4, None),)
    >>> decode_numbers(bytes(8)), decode_numbers(b"\\xff" + bytes(16)), decode_numbers(bytes(17))
    ((), (), ())
    """
    if len(field) == 1:
        return ((field[0], None),)
    if len(field) < 1 + PREFIX_SIZE or (len(field) - 1) % PREFIX_SIZE:
        return ()
    first = field[0]
    prefixes = [field[i : i + PREFIX_SIZE] for i in range(1, len(field), PREFIX_SIZE)]
    if first + len(prefixes) > ROSTER_MAX or len(set(prefixes)) != len(prefixes):
        return ()
    return tuple((first + n, prefix) for n, prefix in enumerate(prefixes))


def encode_introduced_at(ref: IntroRef) -> bytes:
    return bytes([ref.introducer]) + ref.index


def decode_introduced_at(field: bytes) -> IntroRef | None:
    """
    >>> ref = IntroRef(2, bytes(104))
    >>> decode_introduced_at(encode_introduced_at(ref)) == ref
    True
    >>> decode_introduced_at(b"short") is None
    True
    """
    if len(field) != 1 + INDEX_SIZE:
        return None
    return IntroRef(field[0], field[1:])


class Codec(Protocol):
    def encode(self, message: Message) -> bytes: ...

    def decode(self, plaintext: bytes) -> Message | None: ...


VERSION = 3
"""The message version :class:`CborCodec` writes, katzenqt's
``GROUP_CHAT_VERSION``."""


class CborCodec:
    """A plain encoding of :class:`Message`; a client supplies its own."""

    def encode(self, message: Message) -> bytes:
        gcm: dict[str, object] = {"Version": VERSION}
        if message.content is not None:
            gcm["Content"] = message.content
        if message.introduction is not None:
            gcm["Introduction"] = {
                "DisplayName": message.introduction.name,
                "UniversalReadCap": message.introduction.read_cap,
            }
        if message.numbers:
            gcm["Numbers"] = encode_numbers(message.numbers)
        if message.introduced_at is not None:
            gcm["IntroducedAt"] = encode_introduced_at(message.introduced_at)
        if message.acks:
            gcm["Acks"] = ack_codec.encode(message.acks)
        return cbor2.dumps(gcm)

    def decode(self, plaintext: bytes) -> Message | None:
        """
        >>> codec = CborCodec()
        >>> codec.decode(codec.encode(Message(content=b"hi"))).content
        b'hi'
        >>> codec.decode(b"\\xff") is None
        True
        """
        try:
            gcm = cbor2.loads(plaintext)
            intro = gcm.get("Introduction")
            try:
                acks = ack_codec.decode(gcm.get("Acks") or b"")
            except ack_codec.AcksError:
                acks = {}
            return Message(
                content=gcm.get("Content"),
                introduction=(
                    Introduction(intro["DisplayName"], intro["UniversalReadCap"])
                    if intro
                    else None
                ),
                numbers=decode_numbers(gcm.get("Numbers") or b""),
                introduced_at=decode_introduced_at(gcm.get("IntroducedAt") or b""),
                acks=acks,
            )
        except (cbor2.CBORDecodeError, AttributeError, KeyError, TypeError):
            return None
