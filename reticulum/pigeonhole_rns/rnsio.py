# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""Reticulum plumbing shared by the replica and the client: reaching a
replica destination, keeping a Link to it, and making a request on it."""

from __future__ import annotations

import threading
import time
from typing import Dict, Optional

import RNS

from . import APP_NAME, ASPECT, ASPECT_FILTER, wire


class AnnounceHandler:
    """Feeds replica announces to a callback (dest_hash, identity_hash, bridge)."""

    aspect_filter = ASPECT_FILTER

    def __init__(self, on_replica):
        self.on_replica = on_replica

    def received_announce(self, destination_hash, announced_identity, app_data):
        bridge = bool(app_data) and app_data[0] == 1
        self.on_replica(bytes(destination_hash), bytes(announced_identity.hash), bridge)


def reachable(dests) -> list:
    return [d for d in dests if RNS.Transport.has_path(d)]


def hops(dest: bytes) -> int:
    h = RNS.Transport.hops_to(dest)
    return 1 << 30 if h is None else h


class Links:
    """One Link per replica destination, opened on demand and reopened when
    lost. Requests on a link are serialised; the Link API carries payloads
    over the MDU as Resources by itself."""

    def __init__(self, establish_timeout: float = 20.0, request_timeout: float = 60.0):
        self.establish_timeout = establish_timeout
        self.request_timeout = request_timeout
        self._links: Dict[bytes, RNS.Link] = {}
        self._locks: Dict[bytes, threading.Lock] = {}
        self._mu = threading.Lock()

    def _lock(self, dest: bytes) -> threading.Lock:
        with self._mu:
            return self._locks.setdefault(dest, threading.Lock())

    def _link(self, dest: bytes) -> Optional[RNS.Link]:
        with self._mu:
            link = self._links.get(dest)
        if link is not None and link.status == RNS.Link.ACTIVE:
            return link
        identity = RNS.Identity.recall(dest)
        if identity is None:
            RNS.Transport.request_path(dest)
            deadline = time.time() + self.establish_timeout
            while identity is None and time.time() < deadline:
                time.sleep(0.2)
                identity = RNS.Identity.recall(dest)
            if identity is None:
                return None
        destination = RNS.Destination(identity, RNS.Destination.OUT, RNS.Destination.SINGLE, APP_NAME, ASPECT)
        link = RNS.Link(destination)
        deadline = time.time() + self.establish_timeout
        while link.status != RNS.Link.ACTIVE and time.time() < deadline:
            if link.status == RNS.Link.CLOSED:
                return None
            time.sleep(0.1)
        if link.status != RNS.Link.ACTIVE:
            link.teardown()
            return None
        with self._mu:
            self._links[dest] = link
        return link

    def request(self, dest: bytes, path: str, data: bytes) -> Optional[bytes]:
        """Returns the reply bytes, or None when the replica did not answer."""
        with self._lock(dest):
            link = self._link(dest)
            if link is None:
                return None
            receipt = link.request(path, data, timeout=self.request_timeout)
            if receipt is False or receipt is None:
                return None
            deadline = time.time() + self.request_timeout
            while receipt.status not in (RNS.RequestReceipt.READY, RNS.RequestReceipt.FAILED) and time.time() < deadline:
                time.sleep(0.05)
            if receipt.status != RNS.RequestReceipt.READY:
                return None
            resp = receipt.response
            return bytes(resp) if resp is not None else None

    def peek(self, dest: bytes, box_id: bytes) -> Optional[wire.Reply]:
        raw = self.request(dest, "peek", wire.encode_read(box_id))
        if raw is None:
            return None
        try:
            return wire.decode_reply(raw)
        except wire.WireError:
            return None

    def close(self) -> None:
        with self._mu:
            links = list(self._links.values())
            self._links.clear()
        for link in links:
            try:
                link.teardown()
            except Exception:
                pass
