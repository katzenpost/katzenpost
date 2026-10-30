# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""Rendezvous hashing: every replica scores a box by hashing its identity with
the Box ID, lowest first. Anyone with the same set of replicas computes the
same order, with no coordination."""

from __future__ import annotations

import hashlib
from typing import Callable, Iterable, List

K = 2


def score(identity: bytes, box_id: bytes) -> bytes:
    return hashlib.sha256(identity + box_id).digest()


def order(box_id: bytes, replicas: Iterable[bytes], identity_of: Callable[[bytes], bytes]) -> List[bytes]:
    """Replicas (as destination hashes) in the box's order, by identity."""
    return sorted(replicas, key=lambda r: score(identity_of(r), box_id))


def first(box_id: bytes, replicas: Iterable[bytes], identity_of: Callable[[bytes], bytes], k: int = K) -> List[bytes]:
    return order(box_id, replicas, identity_of)[:k]
