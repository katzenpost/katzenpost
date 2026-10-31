# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""katzenqt1's wire formats, as pigeonhole_protocols' wire package has them:
the GroupChatMessage CBOR and its box framing, the reply to a new member,
and the membership hash. The member (``.member``) reads a message as a
``Message``; what a box holds is a ``GroupChatMessage`` map behind one
framing byte."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Callable, Optional

import cbor2

from .member import ack_codec
from .member.events import JoinReply
from .member.wire import (
    INDEX_SIZE,
    KEY_SIZE,
    ROSTER_MAX,
    Introduction,
    IntroRef,
    Message,
    counter,
    decode_introduced_at,
    decode_numbers,
    encode_introduced_at,
    encode_numbers,
    key_of,
)

READ_CAP_SIZE = 136
HASH_SIZE = 32
VERSION = 3

MSG_TEXT = 0
MSG_INTRODUCTION = 1
MSG_FILE_UPLOAD = 2
MSG_WHO = 3
MSG_REPLY_WHO = 4
MSG_CONTROL = 10

OTHER_KEYS = ("file_upload", "who", "reply_who", "tally")

SENTINEL = bytes(HASH_SIZE)
_OLD_SENTINEL = b"TODOTODOTODOTODOTODOTODOTODOTODO"


def start_of(read_cap: bytes) -> bytes:
    return read_cap[KEY_SIZE:]


def is_sentinel(h: bytes) -> bool:
    return h == SENTINEL or h == _OLD_SENTINEL


def membership_hash(read_caps) -> bytes:
    """SHA-256 under a domain of the members' keys, each once, in byte
    order: katzenqt's canonical_membership_hash."""
    keys = sorted({bytes(key_of(c)) for c in read_caps})
    h = hashlib.sha256(b"KP:membership:v1")
    for k in keys:
        h.update(k)
    return h.digest()


# ---- GroupChatMessage ----


@dataclass
class Gcm:
    """A GroupChatMessage. None is an absent field. ``other`` keeps the
    fields this client does not read, as decoded, in katzenqt's order."""

    version: int = VERSION
    membership_hash: bytes = SENTINEL
    msg_type: int = MSG_TEXT
    text: Optional[str] = None
    introduction: Optional[Introduction] = None
    other: Optional[dict] = None
    acks: Optional[bytes] = None
    numbers: Optional[bytes] = None
    introduced_at: Optional[bytes] = None

    def encode(self) -> bytes:
        m: dict = {"version": self.version, "membership_hash": self.membership_hash, "msg_type": self.msg_type}
        if self.text is not None:
            m["text"] = self.text
        if self.introduction is not None:
            m["introduction"] = {"display_name": self.introduction.name, "read_cap": self.introduction.read_cap}
        for k in OTHER_KEYS:
            if self.other and k in self.other:
                m[k] = self.other[k]
        if self.acks is not None:
            m["acks"] = self.acks
        if self.numbers is not None:
            m["numbers"] = self.numbers
        if self.introduced_at is not None:
            m["introduced_at"] = self.introduced_at
        return cbor2.dumps(m)

    @property
    def control(self) -> bool:
        return self.msg_type in (MSG_CONTROL, MSG_INTRODUCTION)


def decode_gcm(data: bytes) -> Optional[Gcm]:
    """The message a CBOR map holds, or None when katzenqt would refuse it."""
    try:
        m = cbor2.loads(data)
    except Exception:
        return None
    if not isinstance(m, dict):
        return None
    version, h = m.get("version"), m.get("membership_hash")
    if not isinstance(version, int) or version < 0 or version > VERSION:
        return None
    if not isinstance(h, bytes) or len(h) != HASH_SIZE:
        return None
    intro = None
    i = m.get("introduction")
    if isinstance(i, dict):
        name, cap = i.get("display_name"), i.get("read_cap")
        if not isinstance(name, str) or not 1 <= len(name) <= 30 or not isinstance(cap, bytes) or len(cap) != READ_CAP_SIZE:
            return None
        intro = Introduction(name, cap)
    msg_type = m.get("msg_type")
    if msg_type is None:
        if intro is not None:
            msg_type = MSG_INTRODUCTION
        elif m.get("file_upload") is not None:
            msg_type = MSG_FILE_UPLOAD
        elif m.get("who") is not None:
            msg_type = MSG_WHO
        elif m.get("reply_who") is not None:
            msg_type = MSG_REPLY_WHO
        else:
            msg_type = MSG_TEXT
    if not isinstance(msg_type, int) or msg_type > MSG_CONTROL:
        return None
    text = m.get("text")
    if text is not None and not isinstance(text, str):
        return None

    def opt_bytes(k):
        v = m.get(k)
        return v if isinstance(v, bytes) else None

    other = {k: m[k] for k in OTHER_KEYS if m.get(k) is not None}
    return Gcm(version, h, msg_type, text, intro, other or None, opt_bytes("acks"), opt_bytes("numbers"), opt_bytes("introduced_at"))


def to_message(data: bytes) -> Optional[Message]:
    """What a member reads of a message's CBOR; a content message's whole
    CBOR travels as its content, as katzenqt's GcmCodec does."""
    g = decode_gcm(data)
    if g is None:
        return None
    try:
        acks = ack_codec.decode(g.acks or b"")
    except ack_codec.AcksError:
        acks = {}
    return Message(
        content=None if g.control else data,
        introduction=g.introduction if g.msg_type == MSG_INTRODUCTION else None,
        numbers=decode_numbers(g.numbers or b""),
        introduced_at=decode_introduced_at(g.introduced_at or b""),
        acks=acks,
    )


def stamp_of(data: bytes) -> Optional[bytes]:
    """The membership hash a control message or introduction carries, or
    None for the sentinel; content carries its own."""
    g = decode_gcm(data)
    if g is None or not g.control or is_sentinel(g.membership_hash):
        return None
    return g.membership_hash


def of_message(m: Message, stamp: Optional[bytes] = None) -> Optional[Gcm]:
    """The GroupChatMessage a member's message is written as; None when its
    content is not a message. A control message or introduction carries
    ``stamp`` as its membership hash, the sentinel without one."""
    if m.content is not None:
        g = decode_gcm(m.content)
        if g is None:
            return None
    elif m.introduction is not None:
        g = Gcm(membership_hash=stamp or SENTINEL, msg_type=MSG_INTRODUCTION, introduction=m.introduction)
    else:
        g = Gcm(membership_hash=stamp or SENTINEL, msg_type=MSG_CONTROL)
    g.acks = ack_codec.encode(m.acks) or None
    g.numbers = encode_numbers(m.numbers) or None
    g.introduced_at = encode_introduced_at(m.introduced_at) if m.introduced_at is not None else None
    return g


def text_content(hash_: bytes, text: str) -> bytes:
    return Gcm(membership_hash=hash_, msg_type=MSG_TEXT, text=text).encode()


def text_of(content: bytes) -> str:
    """What a content message shows as."""
    g = decode_gcm(content)
    if g is None:
        return "[unreadable message]"
    if g.text is not None:
        return g.text
    if g.msg_type == MSG_FILE_UPLOAD:
        return "[file]"
    return "[message of type %d]" % g.msg_type


class Codec:
    """The member's codec over this wire: content is the GCM CBOR."""

    def encode(self, message: Message) -> bytes:
        g = of_message(message)
        return g.encode() if g is not None else b""

    def decode(self, plaintext: bytes) -> Optional[Message]:
        return to_message(plaintext)


# ---- framing ----

FINAL = b"F"
CONTINUED = b"C"
INDIRECTION = b"I"


@dataclass(frozen=True)
class Chunk:
    kind: bytes  # FINAL, CONTINUED, INDIRECTION or b""
    data: bytes = b""
    total: Optional[int] = None


def frame(cbor: bytes) -> bytes:
    return FINAL + cbor


def unframe(box: bytes) -> Chunk:
    if not box:
        return Chunk(b"")
    tag, rest = box[:1], box[1:]
    if tag in (FINAL, CONTINUED):
        return Chunk(tag, rest)
    if tag == INDIRECTION:
        if len(rest) == 4 + READ_CAP_SIZE:
            return Chunk(tag, rest[4:], int.from_bytes(rest[:4], "big"))
        if len(rest) == READ_CAP_SIZE:
            return Chunk(tag, rest)
    return Chunk(b"")


def box_of(m: Message, stamp: Optional[bytes] = None) -> Optional[bytes]:
    g = of_message(m, stamp)
    return frame(g.encode()) if g is not None else None


def message_of(plaintext: bytes) -> Optional[Message]:
    ch = unframe(plaintext)
    return to_message(ch.data) if ch.kind == FINAL else None


# ---- the reply to a new member ----


def reply_who_encode(reply: JoinReply, name: Callable[[bytes], Optional[str]]) -> bytes:
    """katzenqt's GroupChatReplyWho for a JoinReply: a member with no name
    takes no place, as katzenqt leaves out a member it does not know."""
    please_adds = []
    for m in reply.members:
        p = None
        if m is not None:
            read_cap, start = m
            n = name(key_of(read_cap))
            if n is not None:
                p = {"display_name": n, "read_cap": bytes(key_of(read_cap)) + bytes(start)}
        please_adds.append(p)
    return cbor2.dumps(
        {
            "please_adds": please_adds,
            "rosters": [list(list(e) for e in r) if r is not None else None for r in reply.rosters],
            "introductions": [list(i) for i in reply.introductions],
            "introducer": reply.introducer,
            "newcomer": reply.newcomer,
        }
    )


@dataclass
class ReplyWho:
    please_adds: list  # of (name, read_cap) or None
    rosters: Optional[list]
    introductions: Optional[list]
    introducer: Optional[int]
    newcomer: Optional[int]


def reply_who_decode(data: bytes) -> Optional[ReplyWho]:
    try:
        m = cbor2.loads(data)
    except Exception:
        return None
    if not isinstance(m, dict) or not isinstance(m.get("please_adds"), list):
        return None
    adds = []
    for p in m["please_adds"]:
        if p is None:
            adds.append(None)
            continue
        if not isinstance(p, dict):
            return None
        n, c = p.get("display_name"), p.get("read_cap")
        if not isinstance(n, str) or not isinstance(c, bytes) or len(c) != READ_CAP_SIZE:
            return None
        adds.append((n, c))
    rosters = m.get("rosters")
    if rosters is not None:
        if not isinstance(rosters, list):
            return None
        out = []
        for r in rosters:
            if r is None:
                out.append(None)
                continue
            if not isinstance(r, list):
                return None
            entries = []
            for e in r:
                if not (isinstance(e, (list, tuple)) and len(e) == 2 and isinstance(e[0], int) and (e[1] is None or isinstance(e[1], int))):
                    return None
                entries.append((e[0], e[1]))
            out.append(entries)
        rosters = out
    intros = m.get("introductions")
    if intros is not None:
        if not isinstance(intros, list):
            return None
        out = []
        for i in intros:
            if not (isinstance(i, (list, tuple)) and len(i) == 3 and isinstance(i[0], int) and isinstance(i[1], bytes) and isinstance(i[2], int)):
                return None
            out.append((i[0], i[1], i[2]))
        intros = out
    introducer, newcomer = m.get("introducer"), m.get("newcomer")
    if introducer is not None and not isinstance(introducer, int) or newcomer is not None and not isinstance(newcomer, int):
        return None
    return ReplyWho(adds, rosters, intros, introducer, newcomer)


def to_join_reply(w: ReplyWho) -> Optional[JoinReply]:
    """The JoinReply a reply carries, or None when it carries no rosters or
    cannot be read: katzenqt's acks._join_reply."""
    places = len(w.please_adds)
    if w.rosters is None or w.introducer is None or w.newcomer != places or not w.introducer < places < ROSTER_MAX:
        return None
    if w.please_adds[w.introducer] is None or len(w.rosters) != places:
        return None
    keys = [key_of(p[1]) for p in w.please_adds if p is not None]
    if len(set(keys)) != len(keys):
        return None
    for r in w.rosters:
        for index, slot in r or ():
            if not 0 <= index < ROSTER_MAX or not (slot is None or 0 <= slot < places):
                return None
    intros = tuple(
        (by, index, member)
        for by, index, member in w.introductions or ()
        if 0 <= by < places and 0 <= member < places and len(index) == INDEX_SIZE
    )
    return JoinReply(
        members=tuple((p[1], start_of(p[1])) if p is not None else None for p in w.please_adds),
        rosters=tuple(tuple(r) if r is not None else None for r in w.rosters),
        introductions=intros,
        introducer=w.introducer,
        newcomer=w.newcomer,
    )


def without_rosters(w: ReplyWho) -> Optional[JoinReply]:
    """The JoinReply of a reply that carries no rosters: the members named,
    the introducer first, every roster unknown."""
    if w.rosters is not None:
        return None
    members = []
    seen = set()
    for p in w.please_adds:
        if p is None:
            continue
        k = bytes(key_of(p[1]))
        if k in seen:
            return None
        seen.add(k)
        members.append((p[1], start_of(p[1])))
    places = len(members)
    if not 1 <= places < ROSTER_MAX:
        return None
    return JoinReply(tuple(members), (None,) * places, (), 0, places)


__all__ = [
    "Chunk", "Codec", "Gcm", "Introduction", "IntroRef", "Message", "ReplyWho",
    "box_of", "counter", "decode_gcm", "frame", "key_of", "membership_hash", "message_of",
    "of_message", "reply_who_decode", "reply_who_encode", "stamp_of", "start_of", "text_content", "text_of",
    "to_join_reply", "to_message", "unframe", "without_rosters",
]
