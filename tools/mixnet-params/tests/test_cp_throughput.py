# SPDX-FileCopyrightText: (c) 2024 Eva Infeld
# SPDX-License-Identifier: AGPL-3.0-only

"""Verify the pigeonhole-cp throughput model against the cp-bench
empirical numbers from this branch.

The model is the simple affine ``total = propagation + chunks *
per_chunk`` with chunks computed via the two-level encoder model
(see ``mixnet_params.pigeonhole_geo.copy_stream_elements_required``).
The calibration point is the UFPL=2000 / 64 KB run, so the
predicted-bytes/sec assertion at that row is tight (±10%); the other
rows can drift more because per-chunk-seconds varies slightly with
the chunk-count regime, which the simple model does not capture.
"""

import pytest

from mixnet_params.cp_throughput import (
    DEFAULT_PROPAGATION_SECONDS,
    predict_bytes_per_second,
)
from mixnet_params.pigeonhole_geo import max_plaintext_payload_from_ufpl


# (ufpl, payload_bytes, expected_bps, expected_chunks)
EMPIRICAL = [
    # cp-bench at UFPL=2000.
    (2000, 4096, 33.6, 4),
    (2000, 16384, 44.7, 15),
    (2000, 65536, 48.9, 56),
    # cp-bench at UFPL=8000.
    (8000, 4096, 54.7, 2),
    (8000, 16384, 122.9, 4),
    (8000, 65536, 230.2, 10),
    # cp-bench at UFPL=32000.
    (32000, 65536, 547.1, 4),
]


@pytest.mark.parametrize("ufpl,payload,expected_bps,expected_chunks", EMPIRICAL)
def test_predicted_chunks_match_empirical(ufpl, payload, expected_bps, expected_chunks):
    box = max_plaintext_payload_from_ufpl(ufpl)
    bps, _, chunks = predict_bytes_per_second(payload, box, ufpl)
    assert chunks == expected_chunks, (
        f"UFPL={ufpl}, payload={payload}: chunks {chunks} != empirical {expected_chunks}"
    )


def test_predicted_bps_matches_calibration_point():
    """UFPL=2000 / 64 KB is the calibration point so the bps prediction
    should match the empirical number within 10%."""
    box = max_plaintext_payload_from_ufpl(2000)
    bps, _, _ = predict_bytes_per_second(65536, box, 2000)
    assert abs(bps - 48.9) / 48.9 < 0.10


def test_propagation_dominates_small_payloads():
    """A 4 KB payload at UFPL=8000 (2 chunks) should be propagation-dominated."""
    box = max_plaintext_payload_from_ufpl(8000)
    _, total_s, _ = predict_bytes_per_second(4096, box, 8000)
    # Propagation 30 + 2×23 = 76; propagation share = 30/76 ≈ 0.39.
    propagation_share = DEFAULT_PROPAGATION_SECONDS / total_s
    assert propagation_share > 0.3
