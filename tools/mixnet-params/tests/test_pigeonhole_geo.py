# SPDX-FileCopyrightText: (c) 2024 Eva Infeld
# SPDX-License-Identifier: AGPL-3.0-only

"""Verify the Python port of pigeonhole geometry against values
observed on the running docker mixnet at known UFPL settings.

The expected box-payload-and-chunk-count numbers below come from
the cp-bench tool's empirical output on this branch (commit
3de018df). Each test case asserts both the post-encoder copy-stream
element count and the live-config MaxPlaintextPayloadLength.
"""

import pytest

from mixnet_params.pigeonhole_geo import (
    DEFAULT_REPLICA_NIKE_PUBKEY_SIZE,
    copy_stream_elements_required,
    max_plaintext_payload_from_ufpl,
    total_wrapper_overhead,
)


# cp-bench wraps the user payload with a 4-byte length prefix before
# calling CreateCourierEnvelopesFromPayload; reproduce that here so
# the assertions match the empirical counts cp-bench printed.
PREFIX = 4


def test_total_wrapper_overhead_default_replica_nike():
    """The sum on geometry.go:182-185, with CTIDH1024-X25519 sender
    pubkey (160 bytes), should match the docker mixnet's
    UFPL - MaxPlaintextPayloadLength = 32000 - 31549 = 451 observed
    on the running config."""
    assert total_wrapper_overhead(DEFAULT_REPLICA_NIKE_PUBKEY_SIZE) == 451


def test_max_plaintext_payload_ufpl_32000_matches_running_config():
    """The docker mixnet at UFPL=32000 reports
    MaxPlaintextPayloadLength = 31549 in the generated
    client.toml."""
    assert max_plaintext_payload_from_ufpl(32000) == 31549


def test_copy_stream_elements_ufpl_2000_64kib():
    box = max_plaintext_payload_from_ufpl(2000)
    chunks = copy_stream_elements_required(65536 + PREFIX, box, 2000)
    # cp-bench empirically observed 56 chunks for 64 KB at UFPL=2000.
    assert chunks == 56


def test_copy_stream_elements_ufpl_8000_64kib():
    box = max_plaintext_payload_from_ufpl(8000)
    chunks = copy_stream_elements_required(65536 + PREFIX, box, 8000)
    # cp-bench empirically observed 10 chunks for 64 KB at UFPL=8000.
    assert chunks == 10


def test_copy_stream_elements_ufpl_32000_64kib():
    box = max_plaintext_payload_from_ufpl(32000)
    chunks = copy_stream_elements_required(65536 + PREFIX, box, 32000)
    # cp-bench empirically observed 4 chunks for 64 KB at UFPL=32000.
    assert chunks == 4


def test_copy_stream_elements_smaller_payloads():
    """cp-bench reported these chunk counts during the UFPL=8000
    sweep on this branch (commit 3de018df comparison data)."""
    box = max_plaintext_payload_from_ufpl(8000)
    assert copy_stream_elements_required(4096 + PREFIX, box, 8000) == 2
    assert copy_stream_elements_required(16384 + PREFIX, box, 8000) == 4


def test_max_plaintext_payload_too_small_raises():
    with pytest.raises(ValueError):
        # 400 bytes UFPL cannot fit the CourierEnvelope and
        # MKEM/BACAP wrappers; geometry.go:191 raises.
        max_plaintext_payload_from_ufpl(400)
