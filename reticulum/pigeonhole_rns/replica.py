# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""The replica daemon: one Reticulum destination with three request paths,
`write` and `read` for clients and `peek` for other replicas, and threads
for forwarding, handoff, garbage collection and announcing."""

from __future__ import annotations

import os
import threading
import time
from typing import Optional

import RNS

from . import APP_NAME, ASPECT, engine, rnsio, wire
from .bridge import BridgeSocket
from .store import Store


class Replica:
    def __init__(
        self,
        configdir: Optional[str],
        storage_dir: str,
        box_plaintext_size: int,
        bridge_socket: Optional[str] = None,
        announce_interval: float = 600.0,
        forward_interval: float = 2.0,
        handoff_interval: float = 30.0,
        k: int = 2,
        loglevel: int = RNS.LOG_NOTICE,
    ):
        os.makedirs(storage_dir, exist_ok=True)
        self.reticulum = RNS.Reticulum(configdir=configdir, loglevel=loglevel)
        identity_path = os.path.join(storage_dir, "identity")
        if os.path.exists(identity_path):
            self.identity = RNS.Identity.from_file(identity_path)
        else:
            self.identity = RNS.Identity()
            self.identity.to_file(identity_path)

        self.destination = RNS.Destination(self.identity, RNS.Destination.IN, RNS.Destination.SINGLE, APP_NAME, ASPECT)
        self.destination.set_proof_strategy(RNS.Destination.PROVE_ALL)
        self.destination.register_request_handler("write", response_generator=self._on_write, allow=RNS.Destination.ALLOW_ALL)
        self.destination.register_request_handler("read", response_generator=self._on_read, allow=RNS.Destination.ALLOW_ALL)
        self.destination.register_request_handler("peek", response_generator=self._on_peek, allow=RNS.Destination.ALLOW_ALL)

        self.bridge = BridgeSocket(bridge_socket) if bridge_socket else None
        # Box plaintext is length prefixed by the client and the AEAD adds a
        # tag. A size of zero accepts any, for a bridge that defers to the
        # mixnet replica's geometry check.
        ciphertext_size = box_plaintext_size + 4 + 16 if box_plaintext_size > 0 else None
        self.engine = engine.Engine(
            Store(os.path.join(storage_dir, "boxes.sqlite")),
            bytes(self.destination.hash),
            bytes(self.identity.hash),
            box_ciphertext_size=ciphertext_size,
            k=k,
            is_bridge=self.bridge is not None,
        )
        self.links = rnsio.Links()
        self.announce_interval = announce_interval
        self.forward_interval = forward_interval
        self.handoff_interval = handoff_interval
        self._stop = threading.Event()
        RNS.Transport.register_announce_handler(rnsio.AnnounceHandler(self._on_announce))

    # ---- announces ----

    def _on_announce(self, dest: bytes, identity_hash: bytes, bridge: bool) -> None:
        if dest == self.engine.self_dest:
            return
        if self.engine.heard(dest, identity_hash, bridge):
            RNS.log("pigeonhole: replica %s%s" % (RNS.prettyhexrep(dest), " (bridge)" if bridge else ""), RNS.LOG_DEBUG)
        else:
            RNS.log("pigeonhole: ignoring announce with a changed key for %s" % RNS.prettyhexrep(dest), RNS.LOG_WARNING)

    def announce(self) -> None:
        self.destination.announce(app_data=bytes([1 if self.bridge else 0]))

    # ---- request handlers, called on Reticulum's threads ----

    def _reachable(self) -> list:
        return rnsio.reachable(d for d in self.engine.peers if d != self.engine.self_dest)

    def _on_write(self, path, data, request_id, link_id, remote_identity, requested_at):
        return self.engine.handle_write(bytes(data), self._reachable())

    def _on_peek(self, path, data, request_id, link_id, remote_identity, requested_at):
        return self.engine.handle_peek(bytes(data), self._bridge_read())

    def _on_read(self, path, data, request_id, link_id, remote_identity, requested_at):
        return self.engine.handle_read(bytes(data), self._reachable(), self.links.peek, self._bridge_read())

    def _bridge_read(self):
        return self.bridge.read if self.bridge is not None else None

    # ---- workers ----

    def _deliver(self, dst: bytes, box_id: bytes, signature: bytes, payload: bytes) -> Optional[int]:
        if dst == engine.BRIDGE:
            return self.bridge.write(box_id, signature, payload) if self.bridge is not None else None
        raw = self.links.request(dst, "write", wire.encode_write(box_id, signature, payload))
        return None if raw is None else raw[0]

    def _forward_loop(self) -> None:
        while not self._stop.wait(self.forward_interval):
            try:
                self.engine.forward_due(self._reachable(), self._deliver)
            except Exception as e:
                RNS.log("pigeonhole: forwarder: %s" % e, RNS.LOG_ERROR)

    def _handoff_loop(self) -> None:
        while not self._stop.wait(self.handoff_interval):
            try:
                self.engine.handoff(self._reachable())
            except Exception as e:
                RNS.log("pigeonhole: handoff: %s" % e, RNS.LOG_ERROR)

    def _gc_loop(self) -> None:
        while not self._stop.wait(3600.0):
            try:
                self.engine.gc()
            except Exception as e:
                RNS.log("pigeonhole: gc: %s" % e, RNS.LOG_ERROR)

    def _announce_loop(self) -> None:
        while True:
            self.announce()
            if self._stop.wait(self.announce_interval):
                return

    def start(self) -> None:
        for fn in (self._announce_loop, self._forward_loop, self._handoff_loop, self._gc_loop):
            threading.Thread(target=fn, daemon=True).start()
        RNS.log("pigeonhole: replica %s up%s" % (RNS.prettyhexrep(self.destination.hash), ", bridge" if self.bridge else ""), RNS.LOG_NOTICE)

    def stop(self) -> None:
        self._stop.set()
        self.links.close()
        if self.bridge is not None:
            self.bridge.close()
        self.engine.store.close()

    def run_forever(self) -> None:
        self.start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()
