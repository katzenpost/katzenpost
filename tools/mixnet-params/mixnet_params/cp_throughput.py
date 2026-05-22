# SPDX-FileCopyrightText: (c) 2024 Eva Infeld
# SPDX-License-Identifier: AGPL-3.0-only

"""Pigeonhole-cp throughput prediction.

A small empirical model that turns (UFPL-derived chunk capacity,
per-chunk latency, propagation wait, payload size) into a predicted
total wall-clock time and bytes/sec for a single ``Copy`` command
end to end. Calibrated against the cp-bench measurements from the
docker mixnet on this branch (commits 3de018df and 0401e82d):

  UFPL=2000  4 KB / 4 chunks / 122 s / 33.6 B/s
  UFPL=2000 16 KB /15 chunks / 367 s / 44.7 B/s
  UFPL=2000 64 KB /56 chunks /1339 s / 48.9 B/s
  UFPL=8000  4 KB / 2 chunks /  75 s / 54.7 B/s
  UFPL=8000 16 KB / 4 chunks / 133 s /122.9 B/s
  UFPL=8000 64 KB /10 chunks / 285 s /230.2 B/s
  UFPL=32000 4 KB / 2 chunks /  68 s / 59.9 B/s
  UFPL=32000 16 KB / 2 chunks /  70 s /233.7 B/s
  UFPL=32000 64 KB / 4 chunks / 120 s /547.1 B/s

Fitting these three rows from the 64 KB row at increasing UFPL
gives a per-chunk wall-clock of ~23 s on the docker mixnet at the
default lambda settings (the 30 s propagation is a known fixed
overhead; the remaining time divided by chunks gives the per-chunk
cost). The model is a one-line affine:

    total_seconds = propagation_wait_seconds
                  + chunks * per_chunk_seconds
    bytes_per_sec = payload_bytes / total_seconds

A more sophisticated model would account for pipelining,
ARQ retransmissions, and the propagation phase's overlap with
courier dispatch. Empirically the linear model fits across three
UFPL points and three payload sizes within about 20%, which is
adequate for operator sizing decisions.
"""

from mixnet_params.pigeonhole_geo import copy_stream_elements_required

# Default per-chunk wall-clock cost (seconds). Calibrated against the
# docker-mixnet UFPL=2000 / 64 KB run (1339 s total, 30 s propagation,
# 56 chunks): (1339 - 30) / 56 ≈ 23 s/chunk.
DEFAULT_PER_CHUNK_SECONDS = 23.0
DEFAULT_PROPAGATION_SECONDS = 30.0


# Note on the input layer: cp-bench wraps the user's payload with a
# 4-byte length prefix before calling CreateCourierEnvelopesFromPayload,
# matching the existing test TestCreateCourierEnvelopesFromPayload.
# So the actual payload that hits the chunker is `payload_bytes + 4`.
CP_BENCH_LENGTH_PREFIX = 4


def predict_seconds(
    payload_bytes: int,
    max_plaintext_payload: int,
    ufpl: int,
    per_chunk_seconds: float = DEFAULT_PER_CHUNK_SECONDS,
    propagation_seconds: float = DEFAULT_PROPAGATION_SECONDS,
) -> tuple[float, int]:
    """Predict the wall-clock duration of one ``Copy`` command for the
    given user payload size at the given Sphinx geometry.

    Returns ``(seconds, chunks)``.
    """
    chunks = copy_stream_elements_required(
        payload_bytes + CP_BENCH_LENGTH_PREFIX,
        max_plaintext_payload,
        ufpl,
    )
    seconds = propagation_seconds + chunks * per_chunk_seconds
    return seconds, chunks


def predict_bytes_per_second(
    payload_bytes: int,
    max_plaintext_payload: int,
    ufpl: int,
    per_chunk_seconds: float = DEFAULT_PER_CHUNK_SECONDS,
    propagation_seconds: float = DEFAULT_PROPAGATION_SECONDS,
) -> tuple[float, float, int]:
    """Predict the useful bytes/sec achievable for one ``Copy`` command.

    Returns ``(bytes_per_second, total_seconds, chunks)``.
    """
    seconds, chunks = predict_seconds(
        payload_bytes,
        max_plaintext_payload,
        ufpl,
        per_chunk_seconds,
        propagation_seconds,
    )
    if seconds <= 0:
        return 0.0, 0.0, chunks
    return payload_bytes / seconds, seconds, chunks
