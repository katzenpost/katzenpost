"""The ``Acks`` field of a group chat message: how many members are
acknowledged, who, then one ``Idx64`` for each.

Pure: bytes in, plain data out; no session, no connection. See "Rosters"
(Layout, Parsing) in the group chat protocol spec. A member is named by its
roster index in the sender's own roster. The names are a list of roster
indexes or a bitmap, whichever is shorter, and the values follow back to
back in ascending order of roster index.

A value is the BACAP ``Idx64`` of the acknowledged box, not its whole
``MessageBoxIndex``: every member holds every member's read cap, and so its
stream's starting index, from which ``advance_index_to`` derives the rest.
A value of eight bytes is shorter than the longest list or bitmap, so the
length of the field no longer says how many values it holds; the field
begins with that count, less one.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

VALUE_SIZE = 8
"""Bytes in one value: a BACAP ``Idx64``, little-endian."""

ROSTER_MAX = 256
"""The most entries a roster holds: roster indexes 0 to 255."""

MAX_NAMING = (ROSTER_MAX + 7) // 8
"""The longest list or bitmap, in bytes."""

IDX64_MAX = (1 << 64) - 1


class AcksError(ValueError):
    """The field is malformed and carries no acknowledgements."""


def name_members(indexes: Sequence[int]) -> bytes:
    """Ascending roster indexes as a list or a bitmap, whichever is shorter.

    >>> name_members([9]).hex()
    '09'
    >>> name_members([3, 12]).hex()
    '030c'
    >>> name_members([3, 12, 13]).hex()
    '100c'
    >>> name_members(range(1, 16)).hex()
    '7fff'
    >>> name_members([])
    b''
    """
    if not indexes:
        return b""
    width = indexes[-1] // 8 + 1
    if len(indexes) <= width:
        return bytes(indexes)
    bitmap = bytearray(width)
    for index in indexes:
        bitmap[index // 8] |= 0x80 >> (index % 8)
    return bytes(bitmap)


def read_members(naming: bytes, count: int) -> list[int]:
    """What precedes ``count`` values: a list when it is ``count`` bytes
    long, a bitmap when it is shorter.

    >>> read_members(bytes.fromhex("030c"), 2)
    [3, 12]
    >>> read_members(bytes.fromhex("100c"), 3)
    [3, 12, 13]
    >>> read_members(bytes.fromhex("0503"), 2)
    Traceback (most recent call last):
        ...
    katzenqt.ack_codec.AcksError: list is not in ascending order
    """
    if len(naming) == count:
        indexes = list(naming)
        if any(a >= b for a, b in zip(indexes, indexes[1:])):
            raise AcksError("list is not in ascending order")
        return indexes
    if len(naming) > count:
        raise AcksError("more naming bytes than values")
    if len(naming) > MAX_NAMING:
        raise AcksError("bitmap is longer than a roster")
    if not naming or naming[-1] == 0:
        raise AcksError("bitmap ends in a zero byte")
    indexes = [
        index
        for index in range(len(naming) * 8)
        if naming[index // 8] & (0x80 >> (index % 8))
    ]
    if len(indexes) != count:
        raise AcksError("bitmap does not name one member per value")
    return indexes


def encode(acks: Mapping[int, int]) -> bytes:
    """The field for ``acks``, a mapping of roster index to ``Idx64``.
    Empty when there is nothing to acknowledge.

    >>> field = encode({12: 7, 3: 2**64 - 1})
    >>> field[:3].hex(), len(field)
    ('01030c', 19)
    >>> field[3:11].hex()
    'ffffffffffffffff'
    >>> encode({})
    b''
    """
    indexes = sorted(acks)
    if indexes and not 0 <= indexes[0] <= indexes[-1] < ROSTER_MAX:
        raise AcksError("roster index out of range")
    if any(not 0 <= acks[index] <= IDX64_MAX for index in indexes):
        raise AcksError("value out of range")
    if not indexes:
        return b""
    return (
        bytes([len(indexes) - 1])
        + name_members(indexes)
        + b"".join(
            acks[index].to_bytes(VALUE_SIZE, "little") for index in indexes
        )
    )


def decode(field: bytes) -> dict[int, int]:
    """Roster index to ``Idx64``, in ascending order of roster index. Raises
    :class:`AcksError` when the field is malformed; the caller then treats
    the message as carrying no acknowledgements.

    >>> decode(encode({9: 5}))
    {9: 5}
    >>> decode(b"")
    {}
    >>> decode(bytes([0, 2, 3]) + bytes(8))
    Traceback (most recent call last):
        ...
    katzenqt.ack_codec.AcksError: more naming bytes than values
    """
    if not field:
        return {}
    count = field[0] + 1
    width = len(field) - 1 - count * VALUE_SIZE
    if width < 0:
        raise AcksError("field shorter than its count")
    indexes = read_members(field[1 : 1 + width], count)
    values = field[1 + width :]
    return {
        index: int.from_bytes(
            values[i * VALUE_SIZE : (i + 1) * VALUE_SIZE], "little"
        )
        for i, index in enumerate(indexes)
    }
