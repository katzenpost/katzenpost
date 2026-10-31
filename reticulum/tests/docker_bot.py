# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""The Reticulum half of the mixnet bridge test.

Runs next to a mesh replica that bridges to a Katzenpost replica. Watches a
jobs directory for files a mixnet test drops: a read capability for a
stream the mixnet client wrote, and a write capability for the stream it
will read. For each job the bot reads box 0 through the mesh, which pulls
it from the mixnet over the bridge, and writes "echo: " plus the text to box
0 of the other stream, which the mesh pushes into the mixnet. A job file
`name.json` is answered with `name.done`, or `name.failed` with the reason.

    python tests/docker_bot.py --config RNSDIR --jobs DIR
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time

import RNS
from hpqc.bacap.stateless import ReadCap, WriteCap

from pigeonhole_rns import PIGEONHOLE_CTX, wire
from pigeonhole_rns.client import AEAD_OVERHEAD, Client, position, unpad


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config")
    ap.add_argument("--jobs", required=True)
    ap.add_argument("--read-timeout", type=float, default=600.0)
    a = ap.parse_args()
    os.makedirs(a.jobs, exist_ok=True)

    # The box size is learned from the first box read.
    c = Client(a.config, box_plaintext_size=0, loglevel=RNS.LOG_NOTICE)
    c.wait_for_replica(timeout=120)
    RNS.log("bot: watching %s" % a.jobs, RNS.LOG_NOTICE)
    done = set()
    while True:
        for name in sorted(os.listdir(a.jobs)):
            if not name.endswith(".json") or name in done:
                continue
            done.add(name)
            base = os.path.join(a.jobs, name[: -len(".json")])
            try:
                with open(os.path.join(a.jobs, name)) as f:
                    job = json.load(f)
                serve(c, job, a.read_timeout)
                open(base + ".done", "w").close()
                RNS.log("bot: %s done" % name, RNS.LOG_NOTICE)
            except Exception as e:  # report, keep serving
                with open(base + ".failed", "w") as f:
                    f.write(str(e))
                RNS.log("bot: %s failed: %s" % (name, e), RNS.LOG_ERROR)
        time.sleep(1.0)


def serve(c: Client, job: dict, read_timeout: float) -> None:
    read_cap = ReadCap.from_bytes(bytes.fromhex(job["readcap"]))
    write_cap = WriteCap.from_bytes(bytes.fromhex(job["writecap"]))
    pos = position(read_cap, 0)
    box_id = pos.box_id(PIGEONHOLE_CTX)
    deadline = time.time() + read_timeout
    while True:
        r = c.read_box(box_id)
        if r is not None and r.code == wire.SUCCESS:
            break
        if time.time() > deadline:
            raise RuntimeError("read timed out, last reply %s" % (None if r is None else r.code))
        time.sleep(2.0)
    text = unpad(pos.open(PIGEONHOLE_CTX, box_id, r.ciphertext, r.signature))
    # The box just read fixes the mixnet's box size for the reply.
    c.box_plaintext_size = len(r.ciphertext) - 4 - AEAD_OVERHEAD
    _, code = c.write_message(write_cap, 0, b"echo: " + text)
    if code not in wire.STORED_CODES:
        raise RuntimeError("write failed with code %s" % code)


if __name__ == "__main__":
    sys.exit(main())
