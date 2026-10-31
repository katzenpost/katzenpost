# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""A katzenqt1 group chat client without IO, after pigeonhole_protocols'
engine package: ``step`` takes the state and one input, from the user or
from the network, and returns the files to keep, what changed, and the
network work it asks for. The caller saves what changed before it carries
any of the work out.

The member state machine (``.member``) is driven as katzenqt's adapter
drives it: ``compose`` for each message sent, ``written`` once its box is
written, ``observe`` for each box read in order, ``handle`` for a new epoch
and a user's scan, and for a new member ``begin_induction``, then once
everything owed is written ``reply``, then ``introduce_now``. The member
never picks a box itself: its pool is emptied once and never refilled.

Messages too long for one box, which katzenqt writes to a substream behind
an 'I' box, are not sent by this client yet and are stepped past when read.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from . import wire
from .member import events as mev
from .member.group import Group, Outgoing
from .member.ledger import Induction
from .member.wire import INDEX_SIZE, KEY_SIZE

ChatID = str
Key = bytes
Index = bytes

MAX_LOG = 10000

NOT_FOUND, TOMBSTONE, DATA = 0, 1, 2


def backoff_ms(n: int) -> int:
    """How long to wait before reading a box that was not there, after n
    misses in a row."""
    return min(60000, 2000 << min(n, 5))


# ---- what the transport hands back ----


@dataclass(frozen=True)
class Keypair:
    write_cap: bytes
    read_cap: bytes
    first: Index


@dataclass(frozen=True)
class Minted:
    voucher: bytes
    payload: bytes
    write_cap: bytes
    read_cap: bytes
    secret_key: bytes


@dataclass(frozen=True)
class Inducted:
    name: str
    mutated_read_cap: bytes
    sealed_reply: bytes


@dataclass(frozen=True)
class Opened:
    who_reply: bytes
    mutated_write_cap: bytes


@dataclass(frozen=True)
class Outcome:
    """What reading a box found, with the index after it for data or a
    tombstone."""

    kind: int
    plaintext: bytes = b""
    next: Optional[Index] = None


# ---- inputs: what a user asks ----


@dataclass(frozen=True)
class Create:
    chat: ChatID
    name: str


@dataclass(frozen=True)
class Join:
    chat: ChatID
    name: str


@dataclass(frozen=True)
class Induct:
    chat: ChatID
    code: str


@dataclass(frozen=True)
class Send:
    chat: ChatID
    text: str


@dataclass(frozen=True)
class Scan:
    chat: ChatID


@dataclass(frozen=True)
class Leave:
    chat: ChatID


@dataclass(frozen=True)
class RemoveMember:
    chat: ChatID
    who: Key


@dataclass(frozen=True)
class Clear:
    chat: ChatID


@dataclass(frozen=True)
class Rename:
    chat: ChatID
    to: str


# ---- inputs: what came of an action ----


@dataclass(frozen=True)
class Created:
    chat: ChatID
    joining: bool
    keypair: Keypair


@dataclass(frozen=True)
class Wrote:
    chat: ChatID
    job: int
    index: Index
    next: Index


@dataclass(frozen=True)
class Refused:
    """A write found its box holding other bytes."""

    chat: ChatID
    job: int


@dataclass(frozen=True)
class Read:
    chat: ChatID
    stream: Key
    index: Index
    outcome: Outcome


@dataclass(frozen=True)
class Wake:
    chat: ChatID
    stream: Key


@dataclass(frozen=True)
class ScanRead:
    chat: ChatID
    stream: Key
    index: Index
    outcome: Outcome


@dataclass(frozen=True)
class Walked:
    chat: ChatID
    stream: Key
    target: Optional[Index]
    skipped: Tuple[Index, ...]
    steps: int


@dataclass(frozen=True)
class Derived:
    chat: ChatID
    stream: Key
    indexes: Tuple[Index, ...]


@dataclass(frozen=True)
class MintedIn:
    chat: ChatID
    minted: Minted
    box1: Index


@dataclass(frozen=True)
class OpenedIn:
    chat: ChatID
    opened: Opened


@dataclass(frozen=True)
class JoinerPayload:
    chat: ChatID
    voucher: bytes
    voucher_write_cap: bytes
    payload: bytes
    box1: Index


@dataclass(frozen=True)
class SealedReply:
    chat: ChatID
    inducted: Inducted


@dataclass(frozen=True)
class Published:
    chat: ChatID


@dataclass(frozen=True)
class Epoch:
    n: int


@dataclass(frozen=True)
class Failed:
    chat: ChatID
    what: str


# ---- actions: network or disk work; each comes back as the input named ----


@dataclass(frozen=True)
class DoCreate:
    """A new stream: Created."""

    chat: ChatID
    joining: bool


@dataclass(frozen=True)
class DoWrite:
    """Write a box, retrying until written: Wrote, or Refused."""

    chat: ChatID
    job: int
    write_cap: bytes
    index: Index
    box: bytes


@dataclass(frozen=True)
class DoRead:
    """Read a box once: Read."""

    chat: ChatID
    stream: Key
    read_cap: bytes
    index: Index


@dataclass(frozen=True)
class DoWake:
    """Wake after ms milliseconds."""

    chat: ChatID
    stream: Key
    ms: int


@dataclass(frozen=True)
class DoScanRead:
    chat: ChatID
    stream: Key
    read_cap: bytes
    index: Index


@dataclass(frozen=True)
class DoWalk:
    chat: ChatID
    stream: Key
    start: Index
    targets: Tuple[int, ...]
    keep: int


@dataclass(frozen=True)
class DoDerive:
    chat: ChatID
    stream: Key
    start: Index
    count: int


@dataclass(frozen=True)
class DoMint:
    """Mint a voucher and publish its box 0: MintedIn."""

    chat: ChatID
    write_cap: bytes
    name: str


@dataclass(frozen=True)
class DoAwaitReply:
    """Wait for the reply in box 1 and open it: OpenedIn."""

    chat: ChatID
    secret_key: bytes
    voucher_read_cap: bytes
    box1: Index
    write_cap: bytes


@dataclass(frozen=True)
class DoReadVoucher:
    """Read a voucher's box 0: JoinerPayload."""

    chat: ChatID
    voucher: bytes


@dataclass(frozen=True)
class DoSeal:
    """Seal the reply to a voucher: SealedReply."""

    chat: ChatID
    voucher: bytes
    payload: bytes
    who_reply: bytes


@dataclass(frozen=True)
class DoPublish:
    """Write the sealed reply to box 1, retrying until written: Published."""

    chat: ChatID
    voucher_write_cap: bytes
    box1: Index
    reply: bytes


@dataclass(frozen=True)
class DoDelete:
    file: str


# ---- state ----


@dataclass
class Job:
    """A box to write to our own stream, in order."""

    id: int
    token: Optional[int]
    """The message's, to tell the member when it is written; None for a
    rewrite."""
    index: Optional[Index]
    """Chosen when the job is first sent, given for a rewrite."""
    box: bytes
    """Empty for a tombstone."""
    line: Optional[int] = None


SENT, PENDING = 0, 1


@dataclass
class Notice:
    kind: str
    args: Tuple[str, ...] = ()


@dataclass
class Line:
    id: int
    sender: Optional[Key] = None
    index: Optional[Index] = None
    text: str = ""
    notice: Optional[Notice] = None
    status: int = SENT
    idx64: Optional[int] = None
    time: int = 0


@dataclass
class Joining:
    """Joining a group through a voucher we minted: minting until code is
    set."""

    code: str = ""
    secret_key: bytes = b""
    voucher_read_cap: bytes = b""
    box1: Index = b""


@dataclass
class Sealed:
    name: str
    mutated_read_cap: bytes
    reply: bytes


@dataclass
class Inducting:
    """Inducting a member whose voucher we were given: reading the voucher
    until payload is set."""

    voucher: bytes
    payload: Optional[bytes] = None
    voucher_write_cap: bytes = b""
    box1: Index = b""
    sealing: bool = False
    sealed: Optional[Sealed] = None


@dataclass
class Chat:
    id: ChatID
    name: str
    write_cap: bytes = b""
    next_write: Index = b""
    group: Optional[Group] = None
    cursors: Dict[Key, Index] = field(default_factory=dict)
    """Where we read each member's stream next."""
    names: Dict[Key, str] = field(default_factory=dict)
    jobs: List[Job] = field(default_factory=list)
    log: List[Line] = field(default_factory=list)
    joining: Optional[Joining] = None
    inducting: Optional[Inducting] = None
    next_id: int = 0

    def fresh(self) -> int:
        self.next_id += 1
        return self.next_id - 1

    def job(self, id: int) -> Optional[Job]:
        for j in self.jobs:
            if j.id == id:
                return j
        return None

    def acknowledged(self, line: Line) -> bool:
        """Whether any member has acknowledged our line."""
        if self.group is None or line.idx64 is None:
            return False
        return any(line.idx64 <= n for n in self.group.ledger.acked_by.values())


@dataclass
class State:
    me: str
    chats: List[Chat] = field(default_factory=list)

    def chat(self, id: ChatID) -> Optional[Chat]:
        for c in self.chats:
            if c.id == id:
                return c
        return None

    def chat_named(self, name: str) -> Optional[Chat]:
        for c in self.chats:
            if c.name == name:
                return c
        return None

    def wanted(self, a) -> bool:
        """Whether an action tried again is still of use: its chat is still
        here and, for a voucher's box, still waiting for it."""
        if isinstance(a, DoAwaitReply):
            c = self.chat(a.chat)
            return c is not None and c.joining is not None and c.joining.secret_key == a.secret_key
        if isinstance(a, DoReadVoucher):
            c = self.chat(a.chat)
            return c is not None and c.inducting is not None and c.inducting.payload is None and c.inducting.voucher == a.voucher
        if isinstance(a, (DoWrite, DoRead, DoScanRead, DoWalk, DoDerive)):
            return self.chat(a.chat) is not None
        return True


# ---- results ----


@dataclass
class FileWrite:
    file: str
    data: bytes


@dataclass
class Changes:
    chats: set = field(default_factory=set)
    lines: Dict[ChatID, set] = field(default_factory=dict)
    dropped: Dict[ChatID, set] = field(default_factory=dict)
    removed: set = field(default_factory=set)

    def empty(self) -> bool:
        return not (self.chats or self.lines or self.dropped or self.removed)


@dataclass
class Result:
    """Files to keep, then the state to save, then work to start."""

    files: List[FileWrite] = field(default_factory=list)
    changes: Changes = field(default_factory=Changes)
    actions: list = field(default_factory=list)


def voucher_code(voucher: bytes) -> str:
    return base64.b64encode(voucher).decode()


def voucher_file(group: str) -> str:
    return "voucher-" + slug(group) + ".txt"


def slug(s: str) -> str:
    return "".join(ch if ch.isascii() and ch.isalnum() else "_" for ch in s)


def sanitize(name: str) -> str:
    out = "".join(ch for ch in name if not (ord(ch) < 0x20 or 0x7F <= ord(ch) <= 0x9F))
    return out or "unnamed"


def new_group(read_cap: bytes, *, reply: Optional[mev.JoinReply] = None) -> Group:
    """A member this client writes for: it never allocates a box itself."""
    if reply is None:
        g = Group.found(read_cap, [read_cap], codec=wire.Codec())
    else:
        g = Group.joined(read_cap, reply, codec=wire.Codec())
    g.pool = []
    g.deriving = True
    return g


def membership(g: Group, without: Optional[Key] = None) -> bytes:
    """The sender's view of the group: itself and every member it reads,
    less ``without``."""
    return wire.membership_hash([g.read_cap] + [r.read_cap for k, r in g.readers.items() if k != without])


def stamp(g: Group, m: wire.Message) -> Optional[bytes]:
    """What a message the member composed carries as its membership hash: a
    control message the group as it stands, an Introduction the group
    before the member it introduces; content carries its own."""
    if m.content is not None:
        return None
    if m.introduction is not None:
        return membership(g, bytes(wire.key_of(m.introduction.read_cap)))
    return membership(g)


class Engine:
    def __init__(self, state: State, max_plaintext: int):
        self.state = state
        self.max_plaintext = max_plaintext
        # Under way on the network; not saved, since a restart begins it again.
        self._writing: set = set()
        self._reading: set = set()  # (chat, stream) with a read out or a wake pending
        self._misses: Dict[Tuple[ChatID, Key], int] = {}
        self._now = 0
        self._out = Result()

    # ---- bookkeeping ----

    def _begin(self, now: int) -> None:
        self._now = now
        self._out = Result()

    def _emit(self, a) -> None:
        self._out.actions.append(a)

    def _keep(self, file: str, data: bytes) -> None:
        self._out.files.append(FileWrite(file, data))

    def _dirty(self, c: Chat) -> None:
        self._out.changes.chats.add(c.id)

    def _line_changed(self, c: Chat, id: int) -> None:
        self._out.changes.lines.setdefault(c.id, set()).add(id)

    def _line_dropped(self, c: Chat, id: int) -> None:
        self._out.changes.lines.get(c.id, set()).discard(id)
        self._out.changes.dropped.setdefault(c.id, set()).add(id)

    def _say(self, c: Chat, line: Line) -> int:
        line.id = c.fresh()
        line.time = self._now
        c.log.append(line)
        self._dirty(c)
        self._line_changed(c, line.id)
        if len(c.log) > MAX_LOG:
            for d in c.log[: len(c.log) - MAX_LOG]:
                self._line_dropped(c, d.id)
            c.log = c.log[len(c.log) - MAX_LOG :]
        return line.id

    def _notice(self, c: Chat, kind: str, *args: str) -> None:
        self._say(c, Line(0, notice=Notice(kind, args)))

    # ---- writing ----

    def _enqueue(self, c: Chat, outgoing: List[Outgoing], content: Optional[bytes], line: Optional[int]) -> None:
        """Queue each message to write, in order; line shows the one carrying
        content."""
        for o in outgoing:
            g = c.group
            if g is None:
                continue
            mine = content is not None and o.message.content is not None and o.message.content == content
            box = wire.box_of(o.message, stamp(g, o.message))
            if box is not None and len(box) <= self.max_plaintext:
                c.jobs.append(Job(c.fresh(), o.token, None, box, line if mine else None))
                self._dirty(c)
                continue
            g.abandoned(o.token)
            self._notice(c, "too_long" if mine else "not_written")

    def _rewrite(self, c: Chat, index: Index, box: bytes) -> None:
        c.jobs.append(Job(c.fresh(), None, index, box))
        self._dirty(c)

    # ---- reading ----

    def _deliver(self, c: Chat, sender: Key, index: Index, content: bytes) -> None:
        self._say(c, Line(0, sender=sender, index=index, text=wire.text_of(content)))

    def _drop_lines(self, c: Chat, keep: Callable[[Line], bool]) -> None:
        kept = []
        for line in c.log:
            if keep(line):
                kept.append(line)
            else:
                self._line_dropped(c, line.id)
        if len(kept) != len(c.log):
            self._dirty(c)
        c.log = kept

    def _effects(self, c: Chat, effects: list) -> None:
        for ef in effects:
            if isinstance(ef, mev.WriteBox):
                if ef.plaintext:
                    self._rewrite(c, ef.index, ef.plaintext)
            elif isinstance(ef, mev.WriteTombstone):
                self._rewrite(c, ef.index, b"")
            elif isinstance(ef, mev.ReadBox):
                self._emit(DoScanRead(c.id, ef.stream, ef.read_cap, ef.index))
            elif isinstance(ef, mev.DeriveIndexes):
                self._emit(DoDerive(c.id, ef.stream, ef.start, ef.count))
            elif isinstance(ef, mev.Walk):
                self._emit(DoWalk(c.id, ef.stream, ef.start, tuple(ef.targets), ef.keep))
            elif isinstance(ef, mev.Deliver):
                self._deliver(c, ef.sender, ef.index, ef.content)
            elif isinstance(ef, mev.Expire):
                self._drop_lines(c, lambda l: not (l.sender == ef.sender and l.index == ef.index))

    def _label(self, c: Chat, key: Key) -> str:
        if c.group is not None and c.group.me == key:
            return "me"
        return "~" + c.names.get(key, "?")

    def _remark(self, c: Chat, stream: Key, plaintext: bytes) -> None:
        """Note who an Introduction introduced, or a message this client
        cannot show."""
        ch = wire.unframe(plaintext)
        if ch.kind == wire.FINAL:
            m = wire.to_message(ch.data)
            if m is None or m.introduction is None:
                return
            k = bytes(wire.key_of(m.introduction.read_cap))
            if k not in c.names:
                c.names[k] = m.introduction.name
                self._dirty(c)
            if c.group is not None and c.group.me == k:
                return
            self._notice(c, "member_added", self._label(c, stream), m.introduction.name)
        elif ch.kind == wire.CONTINUED:
            self._notice(c, "unreadable", self._label(c, stream))
        elif ch.kind == wire.INDIRECTION:
            self._notice(c, "not_fetched", self._label(c, stream))

    # ---- under way ----

    def _start_reads(self, c: Chat) -> None:
        g = c.group
        if g is None:
            return
        for r in g.readers.values():
            k = (c.id, r.stream)
            if k in self._reading:
                continue
            at = c.cursors.get(r.stream)
            if at is None:
                at = r.next
                c.cursors[r.stream] = at
                self._dirty(c)
            self._reading.add(k)
            self._emit(DoRead(c.id, r.stream, r.read_cap, at))

    def _start_write(self, c: Chat) -> None:
        if c.id in self._writing or not c.write_cap or not c.jobs:
            return
        j = c.jobs[0]
        if j.index is None:
            j.index = c.next_write
            self._dirty(c)
        self._writing.add(c.id)
        self._emit(DoWrite(c.id, j.id, c.write_cap, j.index, j.box))

    def _start_induction(self, c: Chat) -> None:
        """Seal the new member's reply, once everything owed is written."""
        i, g = c.inducting, c.group
        if i is None or g is None or i.payload is None or i.sealing or i.sealed is not None or any(j.token is not None for j in c.jobs):
            return

        def name(key: bytes) -> Optional[str]:
            if key == g.me:
                return self.state.me
            return c.names.get(bytes(key))

        who = wire.reply_who_encode(g.reply(c.next_write), name)
        self._emit(DoSeal(c.id, i.voucher, i.payload, who))
        i.sealing = True
        self._dirty(c)

    def _pump(self) -> None:
        for c in self.state.chats:
            self._start_write(c)
            self._start_reads(c)
            self._start_induction(c)

    def _stop_reading(self, chat: ChatID, stream: Key) -> None:
        self._reading.discard((chat, stream))

    def _missed(self, chat: ChatID, stream: Key) -> int:
        n = self._misses.get((chat, stream), 0)
        self._misses[(chat, stream)] = n + 1
        return n

    def _hit(self, chat: ChatID, stream: Key) -> None:
        self._misses.pop((chat, stream), None)

    def _follow_reader(self, c: Chat, stream: Key) -> None:
        """Move a cursor that a scan has carried past it."""
        if c.group is None:
            return
        r = c.group.readers.get(stream)
        at = c.cursors.get(stream)
        if r is not None and at is not None and wire.counter(at) < wire.counter(r.next):
            c.cursors[stream] = r.next
            self._dirty(c)

    def _cancel_held(self, c: Chat) -> None:
        if c.group is not None and c.group.ledger.induction is Induction.INDUCTING:
            c.group.cancel_induction()

    # ---- inputs ----

    def _chat(self, id: ChatID) -> Optional[Chat]:
        c = self.state.chat(id)
        if c is not None:
            self._dirty(c)
        return c

    def _handle(self, inp) -> None:
        s = self.state
        if isinstance(inp, Create):
            if (c := s.chat_named(inp.name)) is not None:
                self._notice(c, "name_taken", inp.name)
                return
            c = Chat(inp.chat, inp.name)
            s.chats.append(c)
            self._dirty(c)
            self._emit(DoCreate(c.id, False))
        elif isinstance(inp, Join):
            if (c := s.chat_named(inp.name)) is not None:
                self._notice(c, "name_taken_joining", inp.name)
                return
            c = Chat(inp.chat, inp.name, joining=Joining())
            s.chats.append(c)
            self._dirty(c)
            self._emit(DoCreate(c.id, True))
        elif isinstance(inp, Created):
            c = self._chat(inp.chat)
            if c is None:
                return
            c.write_cap, c.next_write = inp.keypair.write_cap, inp.keypair.first
            if inp.joining:
                self._emit(DoMint(c.id, c.write_cap, s.me))
                self._notice(c, "minting")
                return
            c.group = new_group(inp.keypair.read_cap)
            self._notice(c, "new_group")
        elif isinstance(inp, MintedIn):
            c = self._chat(inp.chat)
            if c is None:
                return
            m = inp.minted
            code = voucher_code(m.voucher)
            self._emit(DoAwaitReply(c.id, m.secret_key, m.read_cap, inp.box1, c.write_cap))
            c.joining = Joining(code, m.secret_key, m.read_cap, inp.box1)
            self._keep(voucher_file(c.name), (code + "\n").encode())
            self._notice(c, "voucher_minted", code, c.name, voucher_file(c.name))
        elif isinstance(inp, OpenedIn):
            c = self._chat(inp.chat)
            if c is None or c.joining is None or not c.joining.code or c.group is not None:
                return
            joined = joined_from(inp.opened)
            if joined is None:
                c.joining = None
                self._notice(c, "reply_unreadable")
                return
            g, who = joined
            for p in who.please_adds:
                if p is not None:
                    c.names[bytes(wire.key_of(p[1]))] = sanitize(p[0])
            wc = inp.opened.mutated_write_cap
            c.group, c.write_cap, c.next_write = g, wc, wc[len(wc) - INDEX_SIZE :]
            c.joining, c.cursors = None, {}
            self._notice(c, "joined")
        elif isinstance(inp, Induct):
            c = self._chat(inp.chat)
            if c is None:
                return
            try:
                voucher = base64.b64decode(inp.code, validate=True)
                if len(voucher) != 32:
                    raise ValueError
            except Exception:
                voucher = None
            if c.group is None:
                self._notice(c, "not_joined_yet")
            elif c.inducting is not None and c.inducting.payload is not None:
                self._notice(c, "already_adding")
            elif voucher is None:
                self._notice(c, "not_a_voucher")
            else:
                c.inducting = Inducting(voucher)
                self._emit(DoReadVoucher(c.id, voucher))
                self._notice(c, "reading_voucher")
        elif isinstance(inp, JoinerPayload):
            c = self._chat(inp.chat)
            if c is None or c.inducting is None or c.inducting.payload is not None or c.inducting.voucher != inp.voucher:
                return
            if c.group is not None:
                self._enqueue(c, c.group.begin_induction(), None, None)
            c.inducting = Inducting(inp.voucher, inp.payload, inp.voucher_write_cap, inp.box1)
        elif isinstance(inp, SealedReply):
            c = self._chat(inp.chat)
            if c is None or c.inducting is None:
                return
            i = c.inducting
            i.sealing = False
            i.sealed = Sealed(inp.inducted.name, inp.inducted.mutated_read_cap, inp.inducted.sealed_reply)
            self._emit(DoPublish(c.id, i.voucher_write_cap, i.box1, i.sealed.reply))
        elif isinstance(inp, Published):
            c = self._chat(inp.chat)
            if c is None or c.inducting is None or c.inducting.sealed is None:
                return
            sealed = c.inducting.sealed
            who = sanitize(sealed.name)
            if c.group is not None:
                self._enqueue(c, [c.group.introduce_now(who, sealed.mutated_read_cap)], None, None)
            self._cancel_held(c)
            c.inducting = None
            c.names[bytes(wire.key_of(sealed.mutated_read_cap))] = who
            self._notice(c, "added", who)
        elif isinstance(inp, Send):
            c = self._chat(inp.chat)
            if c is None:
                return
            g = c.group
            if g is None:
                self._notice(c, "not_joined")
                return
            content = wire.text_content(membership(g), inp.text)
            id = self._say(c, Line(0, sender=g.me, text=inp.text, status=PENDING))
            self._enqueue(c, g.compose(content), content, id)
        elif isinstance(inp, Wrote):
            self._writing.discard(inp.chat)
            c = self._chat(inp.chat)
            if c is None:
                return
            j = c.job(inp.job)
            if j is None:
                return
            c.jobs = [x for x in c.jobs if x.id != inp.job]
            if j.token is not None and c.group is not None:
                c.group.written(j.token, inp.index, j.box)
                c.next_write = inp.next
            if j.line is not None:
                for line in c.log:
                    if line.id == j.line:
                        line.status, line.idx64 = SENT, wire.counter(inp.index)
                        self._line_changed(c, line.id)
        elif isinstance(inp, Refused):
            # The chat's writes stop here: the job stays first, and nothing writes after it.
            if (c := self._chat(inp.chat)) is not None:
                self._notice(c, "desync")
        elif isinstance(inp, Read):
            self._read(inp)
        elif isinstance(inp, Wake):
            self._stop_reading(inp.chat, inp.stream)
        elif isinstance(inp, Scan):
            c = self._chat(inp.chat)
            if c is None or c.group is None:
                return
            for stream in list(c.group.readers):
                self._effects(c, c.group.handle(mev.Scan(stream)))
            self._notice(c, "scanning")
        elif isinstance(inp, Leave):
            c = s.chat(inp.chat)
            if c is None:
                return
            s.chats = [x for x in s.chats if x.id != inp.chat]
            self._writing.discard(inp.chat)
            self._reading = {k for k in self._reading if k[0] != inp.chat}
            self._misses = {k: v for k, v in self._misses.items() if k[0] != inp.chat}
            self._out.changes.chats.discard(inp.chat)
            self._out.changes.lines.pop(inp.chat, None)
            self._out.changes.dropped.pop(inp.chat, None)
            self._out.changes.removed.add(inp.chat)
        elif isinstance(inp, RemoveMember):
            c = self._chat(inp.chat)
            if c is None:
                return
            if c.group is None or inp.who not in c.group.readers:
                self._notice(c, "no_longer_member")
                return
            label = self._label(c, inp.who)
            c.group.remove(inp.who)
            self._stop_reading(c.id, inp.who)
            self._hit(c.id, inp.who)
            self._drop_lines(c, lambda l: l.sender != inp.who)
            c.cursors.pop(inp.who, None)
            self._notice(c, "stopped_reading", label)
        elif isinstance(inp, Clear):
            if (c := self._chat(inp.chat)) is not None:
                self._drop_lines(c, lambda l: False)
        elif isinstance(inp, Rename):
            c = self._chat(inp.chat)
            if c is None or not inp.to or inp.to == c.name:
                return
            if s.chat_named(inp.to) is not None:
                self._notice(c, "name_taken", inp.to)
                return
            old = c.name
            c.name = inp.to
            self._notice(c, "renamed", old)
        elif isinstance(inp, ScanRead):
            c = self._chat(inp.chat)
            if c is None or c.group is None:
                return
            res, nxt = read_result(inp.outcome)
            self._effects(c, c.group.handle(mev.BoxRead(inp.stream, inp.index, res, nxt)))
            self._follow_reader(c, inp.stream)
        elif isinstance(inp, Walked):
            c = self._chat(inp.chat)
            if c is None or c.group is None:
                return
            self._effects(c, c.group.handle(mev.Walked(inp.stream, inp.target, tuple(inp.skipped), inp.steps)))
            self._follow_reader(c, inp.stream)
        elif isinstance(inp, Derived):
            c = self._chat(inp.chat)
            if c is None or c.group is None:
                return
            self._effects(c, c.group.handle(mev.IndexesDerived(inp.stream, tuple(inp.indexes))))
        elif isinstance(inp, Epoch):
            for c in s.chats:
                if c.group is None or c.group.epoch >= inp.n:
                    continue
                self._dirty(c)
                self._effects(c, c.group.handle(mev.EpochChanged(inp.n)))
        elif isinstance(inp, Failed):
            c = self._chat(inp.chat)
            if c is None:
                return
            # A chat still joining stays so, and joins on when resumed.
            self._cancel_held(c)
            c.inducting = None
            self._notice(c, "action_failed", inp.what)

    def _read(self, inp: Read) -> None:
        self._stop_reading(inp.chat, inp.stream)
        c = self.state.chat(inp.chat)
        if c is None:
            return
        at = c.cursors.get(inp.stream)
        if at is None or at != inp.index:
            return
        o = inp.outcome
        if o.kind == NOT_FOUND:
            self._reading.add((inp.chat, inp.stream))
            self._emit(DoWake(inp.chat, inp.stream, backoff_ms(self._missed(inp.chat, inp.stream))))
            return
        assert o.next is not None
        self._hit(inp.chat, inp.stream)
        self._dirty(c)
        if o.kind == TOMBSTONE:
            c.cursors[inp.stream] = o.next
            return
        self._remark(c, inp.stream, o.plaintext)
        if c.group is not None:
            ch = wire.unframe(o.plaintext)
            self._effects(c, c.group.observe(inp.stream, inp.index, ch.data if ch.kind == wire.FINAL else None, o.next))
        c.cursors[inp.stream] = o.next

    # ---- the two entry points ----

    def step(self, now: int, inp) -> Result:
        """One input at time now, in milliseconds since the Unix epoch."""
        self._begin(now)
        self._handle(inp)
        self._pump()
        return self._out

    def resume(self, now: int) -> Result:
        """Begin again after a restart: whatever was under way is started
        afresh."""
        self._begin(now)
        for c in self.state.chats:
            if not c.write_cap:
                self._emit(DoCreate(c.id, c.joining is not None))
                continue
            if (j := c.joining) is not None:
                if not j.code:
                    self._emit(DoMint(c.id, c.write_cap, self.state.me))
                else:
                    self._emit(DoAwaitReply(c.id, j.secret_key, j.voucher_read_cap, j.box1, c.write_cap))
            if (i := c.inducting) is not None:
                if i.payload is None:
                    self._emit(DoReadVoucher(c.id, i.voucher))
                elif i.sealed is not None:
                    self._emit(DoPublish(c.id, i.voucher_write_cap, i.box1, i.sealed.reply))
                elif i.sealing:
                    # The sealed reply was never kept, so never published: seal it again.
                    i.sealing = False
                    self._dirty(c)
        self._pump()
        return self._out


def read_result(o: Outcome):
    """A box a scan read, as the member takes it."""
    if o.kind == NOT_FOUND:
        return mev.Missing.NOT_FOUND, None
    if o.kind == TOMBSTONE:
        return mev.Missing.TOMBSTONE, o.next
    ch = wire.unframe(o.plaintext)
    return (ch.data if ch.kind == wire.FINAL else b""), o.next


def joined_from(o: Opened):
    """The group a reply to our voucher puts us in, with the reply, or None."""
    who = wire.reply_who_decode(o.who_reply)
    if who is None or len(o.mutated_write_cap) < KEY_SIZE:
        return None
    reply = wire.to_join_reply(who)
    if reply is None:
        reply = wire.without_rosters(who)
    if reply is None:
        return None
    own = o.mutated_write_cap[KEY_SIZE:]
    for m in reply.members:
        if m is not None and wire.key_of(m[0]) == wire.key_of(own):
            return None
    return new_group(own, reply=reply), who


PLAIN = {
    "name_taken": "you already have a group called {0}",
    "name_taken_joining": "you already have a group called {0}: to join someone else's group, give it a name of its own",
    "minting": "minting a voucher",
    "new_group": "a new group: adding a member's voucher code adds them",
    "voucher_minted": "give the voucher code to a member of the group (it is also in {2})",
    "reply_unreadable": "the reply to our voucher cannot be read",
    "joined": "joined the group",
    "not_joined_yet": "join or create the group first",
    "already_adding": "already adding a member",
    "not_a_voucher": "that is not a voucher code",
    "reading_voucher": "reading the voucher",
    "added": "added ~{0}: they now read everything said in this group",
    "not_joined": "this conversation has not been joined yet",
    "scanning": "scanning for missed messages",
    "no_longer_member": "that member is no longer in this group",
    "stopped_reading": "stopped reading {0} and deleted what they sent; they can still read this group",
    "renamed": "renamed from {0}",
    "action_failed": "{0}",
    "too_long": "that message is too long to send",
    "not_written": "a message could not be written",
    "member_added": "{0} added ~{1}",
    "unreadable": "{0} sent a message that cannot be read",
    "not_fetched": "{0} sent a message that could not be fetched",
    "desync": "a box of our stream holds something else: is this group used from another client?",
}


def plain(n: Notice) -> str:
    """A notice in words, as pigeonhole_protocols' plain presentation."""
    try:
        return PLAIN[n.kind].format(*n.args)
    except (KeyError, IndexError):
        return "notice %s %r" % (n.kind, n.args)
