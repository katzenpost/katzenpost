# SPDX-FileCopyrightText: (c) 2024 Eva Infeld
# SPDX-License-Identifier: AGPL-3.0-only

"""mixnet_params: capacity calculator for mixnet parameters.

The Echomix design exposes a small set of operator-tunable rates
(LambdaP, LambdaL, LambdaM, average per-hop delay, topology width) that
together determine the steady-state traffic each mix node must handle.
This package wraps that arithmetic behind a single CLI so operators do
not have to redo the calculation by hand when tuning a deployment.

Importing the package exposes the pure-function helpers
``max_ops``, ``traffic_per_layer`` and ``traffic_per_node`` so they can
be reused in higher-level scripts.
"""

from mixnet_params.cli import main, max_ops, traffic_per_layer, traffic_per_node

__all__ = [
    "main",
    "max_ops",
    "traffic_per_layer",
    "traffic_per_node",
]
