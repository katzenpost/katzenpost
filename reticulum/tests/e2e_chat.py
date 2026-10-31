# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""End to end: two replica processes on a local Reticulum network and two
chat clients, each a process driven through its standard input. alice
founds a group, bob joins through a voucher alice inducts, and they talk.

    python tests/e2e_chat.py --run-dir /path/to/scratch

Not collected by pytest: it spawns processes and binds a TCP port."""

from __future__ import annotations

import argparse
import os
import queue
import shutil
import subprocess
import sys
import threading
import time

from e2e_two_replicas import HUB_CONFIG, LEAF_CONFIG, write_config

# A voucher payload is about 450 bytes and the sealed reply to it more; the mixnet uses boxes of a kilobyte or two.
BOX = 1000


class Proc:
    """A chat client process: lines in, lines out."""

    def __init__(self, name: str, args: list, env: dict, cwd: str, log):
        self.name = name
        self.p = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log, env=env, cwd=cwd, text=True, bufsize=1)
        self.lines: "queue.Queue[str]" = queue.Queue()
        self.seen: list = []
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self) -> None:
        assert self.p.stdout is not None
        for line in self.p.stdout:
            line = line.rstrip("\n")
            print("  %s> %s" % (self.name, line), flush=True)
            self.lines.put(line)

    def say(self, cmd: str) -> None:
        print("%s< %s" % (self.name, cmd), flush=True)
        assert self.p.stdin is not None
        self.p.stdin.write(cmd + "\n")
        self.p.stdin.flush()

    def expect(self, needle: str, timeout: float) -> str:
        deadline = time.time() + timeout
        while True:
            left = deadline - time.time()
            if left <= 0:
                raise TimeoutError("%s: no line containing %r" % (self.name, needle))
            try:
                line = self.lines.get(timeout=min(left, 1.0))
            except queue.Empty:
                continue
            self.seen.append(line)
            if needle in line:
                return line

    def close(self) -> None:
        try:
            self.say("quit")
            self.p.wait(timeout=15)
        except Exception:
            self.p.kill()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--settle", type=float, default=10.0)
    a = ap.parse_args()

    run = os.path.abspath(a.run_dir)
    if os.path.isdir(run):
        shutil.rmtree(run)
    os.makedirs(run)
    here = os.path.dirname(os.path.abspath(__file__))
    pkg_root = os.path.dirname(here)
    env = dict(os.environ, PYTHONPATH=pkg_root)

    procs = []
    chats = []
    try:
        for name, cfg in (("a", HUB_CONFIG), ("b", LEAF_CONFIG)):
            cfgdir = write_config(os.path.join(run, "rns-" + name), cfg)
            log = open(os.path.join(run, "replica-%s.log" % name), "w")
            procs.append(
                subprocess.Popen(
                    [sys.executable, "-m", "pigeonhole_rns.cli", "--config", cfgdir, "--box-size", str(BOX), "-v",
                     "replica", "--storage", os.path.join(run, "store-" + name), "--announce-interval", "3"],
                    stdout=log, stderr=subprocess.STDOUT, env=env, cwd=pkg_root,
                )
            )
            time.sleep(2.0)
        time.sleep(a.settle)

        def chat(name: str) -> Proc:
            cfgdir = write_config(os.path.join(run, "rns-" + name), LEAF_CONFIG)
            log = open(os.path.join(run, "chat-%s.log" % name), "w")
            c = Proc(
                name,
                [sys.executable, "-m", "pigeonhole_rns.chat.cli", "--config", cfgdir, "--state", os.path.join(run, "chat-" + name),
                 "--name", name, "--box-size", str(BOX), "--epoch-poll", "5"],
                env, pkg_root, log,
            )
            chats.append(c)
            return c

        alice, bob = chat("alice"), chat("bob")
        time.sleep(a.settle)

        alice.say("create g")
        alice.expect("a new group", 60)
        bob.say("join g")
        bob.expect("give the voucher code", 120)
        code = open(os.path.join(run, "chat-bob", "voucher-g.txt")).read().strip()
        alice.say("induct g " + code)
        alice.expect("added ~bob", 180)
        bob.expect("joined the group", 180)

        alice.say("send g hello bob, you coming to the party later tonight?")
        bob.expect("alice: hello bob, you coming to the party later tonight?", 180)
        bob.say("send g yo what up? yes")
        alice.expect("bob: yo what up? yes", 180)

        bob.say("members g")
        bob.expect("~alice", 10)
        print("PASS")
        return 0
    except Exception as e:
        print("FAIL:", e, file=sys.stderr)
        return 1
    finally:
        for c in chats:
            c.close()
        for p in procs:
            p.terminate()
        for p in procs:
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()


if __name__ == "__main__":
    sys.exit(main())
