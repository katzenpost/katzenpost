# SPDX-FileCopyrightText: (c) 2024 Eva Infeld
# SPDX-License-Identifier: AGPL-3.0-only

"""mixnet_params: capacity calculator for Echomix parameters.

The Echomix design exposes a small set of operator-tunable rates
(LambdaP, LambdaL, LambdaM, LambdaG, LambdaR, per-hop mix delay,
topology width) that together determine the steady-state traffic
each mix node must handle, the courier→replica drain budget, and the
MKEM Decapsulate budget on the replicas. This package wraps that
arithmetic plus the precise Sphinx+pigeonhole geometry overheads
behind a single CLI so operators do not have to redo the calculation
by hand when tuning a deployment.

Importing the package exposes the pure-function helpers from each
submodule so they can be reused in higher-level scripts:

  - :mod:`mixnet_params.sphinx_geo`
    Sphinx packet geometry arithmetic.
  - :mod:`mixnet_params.pigeonhole_geo`
    Pigeonhole/BACAP/MKEM/CourierEnvelope overhead arithmetic.
  - :mod:`mixnet_params.cp_throughput`
    Pigeonhole-cp wall-clock and bytes/sec predictor.
"""

from mixnet_params.cli import (
    main,
    max_ops,
    traffic_per_layer,
    traffic_per_node,
)
from mixnet_params.pigeonhole_geo import (
    copy_stream_element_capacity_bytes,
    copy_stream_elements_required,
    envelope_capacity_bytes,
    envelopes_required,
    max_plaintext_payload_from_ufpl,
)
from mixnet_params.cp_throughput import (
    predict_bytes_per_second,
    predict_seconds,
)

__all__ = [
    "main",
    "max_ops",
    "traffic_per_layer",
    "traffic_per_node",
    "copy_stream_element_capacity_bytes",
    "copy_stream_elements_required",
    "envelope_capacity_bytes",
    "envelopes_required",
    "max_plaintext_payload_from_ufpl",
    "predict_bytes_per_second",
    "predict_seconds",
]
