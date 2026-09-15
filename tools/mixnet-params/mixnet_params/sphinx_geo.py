# SPDX-FileCopyrightText: (c) 2024 Eva Infeld
# SPDX-License-Identifier: AGPL-3.0-only

"""Sphinx packet geometry arithmetic.

Pure-function port of the formulas in
``core/sphinx/geo/geo.go`` (katzenpost monorepo). Each function takes
plain ints and returns plain ints; the constants below are exactly
the named constants from the Go side and any future change there is
a one-for-one diff here.

The "NIKE" and "KEM" variants of ``header_length`` share the same
arithmetic; the only difference is whether the caller passes the
NIKE public-key size or the KEM ciphertext size for the
``key_material_bytes`` argument.
"""

# Constants from core/sphinx/geo/geo.go and core/sphinx/internal/crypto/crypto.go.
AD_LENGTH = 2  # geo.go:29
PAYLOAD_TAG_LENGTH = 32  # geo.go:32
SPHINX_PLAINTEXT_HEADER_LENGTH = 2  # geo.go:27 (= 1 + 1)
MAC_LENGTH = 32  # crypto.go:45
SPRP_KEY_LENGTH = 48  # crypto.go:54
SPRP_IV_LENGTH = 16  # crypto.go:57
SPRP_KEY_MATERIAL_LENGTH = SPRP_KEY_LENGTH + SPRP_IV_LENGTH
COMMAND_TAG_LENGTH = 1  # constants
NODE_ID_LENGTH = 32  # constants

# Default Sphinx UFPL across genconfig + the docker Makefile.
DEFAULT_USER_FORWARD_PAYLOAD_LENGTH = 2000


def per_hop_routing_info_length(key_material_bytes: int = SPRP_KEY_MATERIAL_LENGTH) -> int:
    """Per-hop routing info: one command tag + node ID + MAC + SPRP key
    material (the key+IV the unwrapping uses for the next hop)."""
    return COMMAND_TAG_LENGTH + NODE_ID_LENGTH + MAC_LENGTH + key_material_bytes


def routing_info_length(nr_hops: int, per_hop_bytes: int) -> int:
    """The cumulative routing info field across all hops."""
    return per_hop_bytes * nr_hops


def header_length(scheme_key_bytes: int, routing_info_bytes: int) -> int:
    """Sphinx header. The same formula holds for NIKE and KEM variants;
    pass the NIKE public-key size or the KEM ciphertext size for
    ``scheme_key_bytes`` as appropriate.

    From geo.go:248 (NIKE) and geo.go:251 (KEM):
        adLength + key_or_ct_size + routingInfoLength + MACLength
    """
    return AD_LENGTH + scheme_key_bytes + routing_info_bytes + MAC_LENGTH


def surb_length(header_bytes: int) -> int:
    """A SURB carries a full Sphinx header, a NodeID, and the SPRP key
    material the receiver will use to decrypt the SURB-attached
    payload (geo.go:260)."""
    return header_bytes + NODE_ID_LENGTH + SPRP_KEY_MATERIAL_LENGTH


def derive_forward_payload_length(user_forward_payload_length: int, surb_bytes: int) -> int:
    """The ``with-SURB`` case from geo.go:264. The forward payload
    carries a one-byte SURB flag, a one-byte ?? plus the SURB itself
    and the user's payload bytes."""
    return user_forward_payload_length + SPHINX_PLAINTEXT_HEADER_LENGTH + surb_bytes


def packet_length(header_bytes: int, forward_payload_bytes: int) -> int:
    """Total wire size of a Sphinx packet (geo.go:256):
    header + payload-tag + forward-payload."""
    return header_bytes + PAYLOAD_TAG_LENGTH + forward_payload_bytes
