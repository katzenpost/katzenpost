"""Record what each member of a simulated group was told and what it did,
for checking against CryptWalker's Lean model of a member
(``lake exe CryptWalker.Protocols.GroupComm.GroupChatKatzenqt1.replay``).

A :class:`TracedGroup` is a :class:`~.group.Group` that writes one JSON line
per call made on it from outside: what was called, with what, what it
returned, and the member's whole state afterwards, in the shape
:mod:`~.state` keeps it. Messages are written decoded, since the Lean model
leaves encoding to the client. Bytes are hex.
"""

from __future__ import annotations

import dataclasses
import enum
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import IO, Any

from . import state
from .events import JoinReply
from .group import Group, Outgoing
from .wire import Codec, IntroRef, Key, Message


class Recorder:
    def __init__(self, out: IO[str], name_of: Callable[[Key], str] = lambda key: key.hex()):
        self.out = out
        self.name_of = name_of

    def line(self, group: Group, call: str, args: dict[str, Any], result: Any) -> None:
        record = {
            "member": self.name_of(group.me),
            "me": group.me.hex(),
            "call": call,
            "args": args,
            "result": result,
            "state": snapshot(group),
        }
        self.out.write(json.dumps(record, sort_keys=True) + "\n")


def message(value: Message | None) -> Any:
    if value is None:
        return None
    return {
        "content": value.content,
        "introduction": (
            {"name": value.introduction.name, "read_cap": value.introduction.read_cap}
            if value.introduction
            else None
        ),
        "numbers": [[k, ref] for k, ref in value.numbers],
        "introduced_at": value.introduced_at,
        "acks": sorted(value.acks.items()),
    }


def decoded(codec: Codec, plaintext: bytes | None) -> Any:
    return message(codec.decode(plaintext)) if plaintext else None


def payload(codec: Codec, plaintext: bytes | None) -> Any:
    """What a box of our own stream holds: the message, decoded, or bytes a
    client handed over that are not one, which the member never looks into."""
    if plaintext is None:
        return None
    decoded = codec.decode(plaintext)
    return message(decoded) if decoded is not None else {"bytes": plaintext}


def plain(value: Any, codec: Codec) -> Any:
    """``value`` as JSON: dataclasses as objects named by ``type``, bytes as
    hex, messages decoded."""
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, Message):
        return plain(message(value), codec)
    if isinstance(value, IntroRef):
        return [value.introducer, value.index.hex()]
    if isinstance(value, enum.Enum):
        return value.value
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        fields = {f.name: getattr(value, f.name) for f in dataclasses.fields(value)}
        if "result" in fields and isinstance(fields["result"], bytes):
            fields["result"] = {"data": decoded(codec, fields["result"])}
        if "plaintext" in fields and isinstance(fields["plaintext"], bytes):
            fields["payload"] = payload(codec, fields.pop("plaintext"))
        return {"type": type(value).__name__, **{k: plain(v, codec) for k, v in fields.items()}}
    if isinstance(value, dict):
        return {str(k): plain(v, codec) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [plain(item, codec) for item in value]
    return value


def snapshot(group: Group) -> Any:
    body = state._encode(group)
    for pair in body["sent"]["records"]:
        pair[1]["plaintext"] = payload(group.codec, pair[1]["plaintext"])
    return plain(body, group.codec)


@dataclass
class TracedGroup(Group):
    tracer: Recorder | None = field(default=None, compare=False, repr=False)
    depth: int = field(default=0, compare=False, repr=False)

    @classmethod
    def found(cls, read_cap: bytes, founders: list[bytes], **kwargs: Any) -> TracedGroup:
        group = super().found(read_cap, founders, **kwargs)
        assert isinstance(group, TracedGroup)
        group.log("found", {"read_cap": read_cap, "founders": founders}, None)
        return group

    @classmethod
    def joined(cls, read_cap: bytes, reply: JoinReply, **kwargs: Any) -> TracedGroup:
        group = super().joined(read_cap, reply, **kwargs)
        assert isinstance(group, TracedGroup)
        group.log("joined", {"read_cap": read_cap, "reply": reply}, None)
        return group

    @classmethod
    def of(cls, group: Group, tracer: Recorder | None) -> TracedGroup:
        """``group``, traced from here on: as when a traced member is
        restored from its bytes."""
        fields = {f.name: getattr(group, f.name) for f in dataclasses.fields(Group)}
        return cls(**fields, tracer=tracer)

    def log(self, call: str, args: dict[str, Any], result: Any) -> None:
        if self.tracer is not None and self.depth == 0:
            settings = {"policy": self.policy, "recheck": self.recheck}
            self.tracer.line(
                self, call, plain({**args, **settings}, self.codec), plain(result, self.codec)
            )

    def traced(self, call: str, run: Callable[[], Any], **args: Any) -> Any:
        self.depth += 1
        try:
            result = run()
        finally:
            self.depth -= 1
        self.log(call, args, result)
        return result

    def handle(self, event: Any) -> Any:
        return self.traced("handle", lambda: super(TracedGroup, self).handle(event), event=event)

    def observe(
        self, stream: Key, index: bytes, plaintext: bytes | None, next_index: bytes
    ) -> Any:
        return self.traced(
            "observe",
            lambda: super(TracedGroup, self).observe(stream, index, plaintext, next_index),
            stream=stream, index=index, message=decoded(self.codec, plaintext), next=next_index,
        )

    def compose(self, content: bytes | None = None) -> list[Outgoing]:
        result: list[Outgoing] = self.traced(
            "compose", lambda: super(TracedGroup, self).compose(content), content=content
        )
        return result

    def written(self, token: int, index: bytes, plaintext: bytes | None = None) -> None:
        self.traced(
            "written",
            lambda: super(TracedGroup, self).written(token, index, plaintext),
            token=token, index=index, payload=payload(self.codec, plaintext),
        )

    def abandoned(self, token: int) -> None:
        self.traced("abandoned", lambda: super(TracedGroup, self).abandoned(token), token=token)

    def begin_induction(self) -> list[Outgoing]:
        result: list[Outgoing] = self.traced(
            "begin_induction", lambda: super(TracedGroup, self).begin_induction()
        )
        return result

    def introduce_now(self, name: str, read_cap: bytes) -> Outgoing:
        result: Outgoing = self.traced(
            "introduce_now",
            lambda: super(TracedGroup, self).introduce_now(name, read_cap),
            name=name, read_cap=read_cap,
        )
        return result

    def cancel_induction(self) -> None:
        self.traced("cancel_induction", lambda: super(TracedGroup, self).cancel_induction())

    def reply(self, own_start: bytes) -> JoinReply:
        result: JoinReply = self.traced(
            "reply", lambda: super(TracedGroup, self).reply(own_start), own_start=own_start
        )
        return result

    def remove(self, member: Key) -> None:
        self.traced("remove", lambda: super(TracedGroup, self).remove(member), member=member)

