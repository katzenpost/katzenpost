# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""Pigeonhole storage over Reticulum: an open mesh replica, a client, and a
bridge to a Katzenpost mixnet replica on the same host."""

APP_NAME = "pigeonhole"
ASPECT = "replica"
ASPECT_FILTER = APP_NAME + "." + ASPECT

# BACAP context shared with Katzenpost clients, so boxes cross unchanged.
PIGEONHOLE_CTX = b"pigeonhole context"
