"""Carrying out a :class:`~.events.Walk`, for the simulator and for the app
alike. An acknowledgement names a box by its ``Idx64``, so the box is the
walk's start advanced to it: BACAP's ``advance_index_to``, no search.
"""

from __future__ import annotations

from hpqc.bacap import MessageBoxIndex

from .events import Walk, Walked


def walk(request: Walk, limit: int) -> Walked:
    """The furthest of ``request.targets`` fewer than ``limit`` boxes ahead
    of its start, how many steps away it is, and the last ``request.keep``
    indexes before it (all of them for ``keep`` 0); no target if none is
    that close.

    >>> from hpqc.bacap import MessageBoxIndex
    >>> start = MessageBoxIndex(10, bytes(32), bytes(32), bytes(32))
    >>> done = walk(Walk(b"s", start.to_bytes(), (12, 9, 500), 1), 256)
    >>> done.target == start.advance_index_to(12).to_bytes(), done.steps
    (True, 2)
    >>> done.skipped == (start.advance_index_to(11).to_bytes(),)
    True
    >>> walk(Walk(b"s", start.to_bytes(), (500,), 1), 256).target is None
    True
    """
    start = MessageBoxIndex.from_bytes(request.start)
    here = start.idx_64
    met = [t for t in request.targets if here <= t < here + limit]
    if not met:
        return Walked(request.stream, None, ())
    target = max(met)
    first = here if request.keep == 0 else max(here, target - request.keep)
    index = start.advance_index_to(first)
    skipped = []
    while index.idx_64 < target:
        skipped.append(index.to_bytes())
        index = index.next_index()
    return Walked(
        request.stream, index.to_bytes(), tuple(skipped), target - here
    )
