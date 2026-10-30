# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""End to end: two replica processes on a local Reticulum network and a
client in this process. Writes a message, reads it back through the entry
replica, checks the other replica received the forward, deletes it, and
reads the tombstone.

    python tests/e2e_two_replicas.py --run-dir /path/to/scratch

Not collected by pytest: it spawns processes and binds a TCP port."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import time

HUB_PORT = 42101
BOX = 100

HUB_CONFIG = """[reticulum]
  enable_transport = Yes
  share_instance = No
[logging]
  loglevel = 3
[interfaces]
  [[Hub]]
    type = TCPServerInterface
    enabled = yes
    listen_ip = 127.0.0.1
    listen_port = %d
""" % HUB_PORT

LEAF_CONFIG = """[reticulum]
  enable_transport = No
  share_instance = No
[logging]
  loglevel = 3
[interfaces]
  [[ToHub]]
    type = TCPClientInterface
    enabled = yes
    target_host = 127.0.0.1
    target_port = %d
""" % HUB_PORT


def write_config(d: str, text: str) -> str:
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "config"), "w") as f:
        f.write(text)
    return d


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--settle", type=float, default=12.0, help="seconds to let announces and paths settle")
    a = ap.parse_args()

    run = os.path.abspath(a.run_dir)
    if os.path.isdir(run):
        shutil.rmtree(run)
    os.makedirs(run)
    here = os.path.dirname(os.path.abspath(__file__))
    pkg_root = os.path.dirname(here)
    env = dict(os.environ, PYTHONPATH=pkg_root)

    procs = []
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

        sys.path.insert(0, pkg_root)
        import RNS
        from hpqc.bacap.stateless import WriteCap

        from pigeonhole_rns import wire
        from pigeonhole_rns.client import Client

        client_cfg = write_config(os.path.join(run, "rns-client"), LEAF_CONFIG)
        c = Client(client_cfg, BOX, loglevel=RNS.LOG_NOTICE)
        if not c.wait_for_replica(timeout=a.settle + 20):
            print("FAIL: no replica announced", file=sys.stderr)
            return 1
        time.sleep(a.settle)
        replicas = list(c.replicas)
        print("replicas heard:", [r.hex()[:8] for r in replicas], "entry:", c.entry().hex()[:8])
        if len(replicas) < 2:
            print("FAIL: expected two replicas", file=sys.stderr)
            return 1

        cap = WriteCap.generate()
        box_id, code = c.write_message(cap, 0, b"yo what up? you coming to the party later tonight?")
        print("write code", code)
        if code not in wire.STORED_CODES:
            print("FAIL: write not stored", file=sys.stderr)
            return 1

        code, text = c.read_message(cap.read_cap(), 0)
        print("read code", code, "text", text)
        if code != wire.SUCCESS or text != b"yo what up? you coming to the party later tonight?":
            print("FAIL: read back mismatch", file=sys.stderr)
            return 1

        # Both replicas hold it once the forward has run.
        deadline = time.time() + 30
        holders = set()
        while time.time() < deadline and len(holders) < 2:
            for r in replicas:
                got = c.read_box(box_id, dest=r, path="peek")
                if got is not None and got.code == wire.SUCCESS:
                    holders.add(r)
            time.sleep(1.0)
        print("holders:", [h.hex()[:8] for h in holders])
        if len(holders) < 2:
            print("FAIL: forward did not reach the second replica", file=sys.stderr)
            return 1

        _, code = c.delete_message(cap, 0)
        print("delete code", code)
        c.tombstones.clear()
        code, _ = c.read_message(cap.read_cap(), 0)
        print("read after delete code", code)
        if code != wire.TOMBSTONE:
            print("FAIL: expected a tombstone", file=sys.stderr)
            return 1

        code, _ = c.read_message(cap.read_cap(), 1)
        print("read of unwritten index code", code)
        if code != wire.NOT_FOUND:
            print("FAIL: expected not found", file=sys.stderr)
            return 1

        c.close()
        print("PASS")
        return 0
    finally:
        for p in procs:
            p.terminate()
        for p in procs:
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()


if __name__ == "__main__":
    sys.exit(main())
