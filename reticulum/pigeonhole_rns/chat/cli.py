# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""A group chat client on the mesh, without a user interface: commands on
standard input, lines as they arrive on standard output.

    pigeonhole-chat --config ~/.reticulum --state ~/chat --name alice --box-size 1000

Commands:
    create GROUP            start a group
    join GROUP              mint a voucher to join someone's group; give them the code
    induct GROUP CODE       add the member whose voucher code this is
    send GROUP TEXT...      say something
    show GROUP              every line of the conversation
    members GROUP
    scan GROUP              look for missed messages
    rename GROUP NEW
    remove GROUP NAME       stop reading a member
    leave GROUP
    quit
"""

from __future__ import annotations

import argparse
import sys
import threading
import uuid

import RNS

from ..client import Client as MeshClient
from . import engine as eng
from .backend import MeshBackend
from .client import Client


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", help="Reticulum config directory")
    ap.add_argument("--state", required=True, help="where this client keeps its state")
    ap.add_argument("--name", required=True, help="our display name")
    ap.add_argument("--box-size", type=int, required=True, help="the replicas' box plaintext size")
    ap.add_argument("--epoch-poll", type=float, default=60.0)
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args()

    mesh = MeshClient(a.config, a.box_size, loglevel=RNS.LOG_DEBUG if a.verbose else RNS.LOG_ERROR)
    if not mesh.wait_for_replica(timeout=60):
        print("no replica heard", file=sys.stderr)
        return 1
    out = threading.Lock()
    shown: dict = {}

    def on_change(ch: eng.Changes) -> None:
        for chat, ids in ch.lines.items():
            name = client.state.chat(chat).name if client.state.chat(chat) else chat
            seen = shown.setdefault(chat, set())
            for line in client.lines(chat):
                if line.id in ids and line.id not in seen:
                    seen.add(line.id)
                    with out:
                        print("[%s] %s" % (name, client.plain(chat, line)), flush=True)

    client = Client(a.state, a.name, MeshBackend(mesh), epoch_poll_s=a.epoch_poll, on_change=on_change)
    for c in client.chats():
        shown[c.id] = {l.id for l in c.log}
    client.start()
    try:
        for raw in sys.stdin:
            words = raw.strip().split(None, 2)
            if not words:
                continue
            cmd = words[0]
            if cmd == "quit":
                break
            if len(words) < 2:
                print("? %s GROUP ..." % cmd, flush=True)
                continue
            group = words[1]
            rest = words[2] if len(words) > 2 else ""
            chat = client.chat_id(group)
            if cmd == "create":
                client.feed(eng.Create(uuid.uuid4().hex, group))
            elif cmd == "join":
                client.feed(eng.Join(uuid.uuid4().hex, group))
            elif chat is None:
                print("? no group called %s" % group, flush=True)
            elif cmd == "induct":
                client.feed(eng.Induct(chat, rest.strip()))
            elif cmd == "send":
                client.feed(eng.Send(chat, rest))
            elif cmd == "show":
                with out:
                    for line in client.lines(chat):
                        print("[%s] %s" % (group, client.plain(chat, line)), flush=True)
            elif cmd == "members":
                with out:
                    for key, name in client.members(chat):
                        print("[%s] ~%s %s" % (group, name, key.hex()[:16]), flush=True)
            elif cmd == "scan":
                client.feed(eng.Scan(chat))
            elif cmd == "rename":
                client.feed(eng.Rename(chat, rest.strip()))
            elif cmd == "remove":
                who = [k for k, n in client.members(chat) if n == rest.strip()]
                if who:
                    client.feed(eng.RemoveMember(chat, who[0]))
                else:
                    print("? no member called %s" % rest.strip(), flush=True)
            elif cmd == "leave":
                client.feed(eng.Leave(chat))
            else:
                print("? unknown command %s" % cmd, flush=True)
    finally:
        client.close()
        mesh.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
