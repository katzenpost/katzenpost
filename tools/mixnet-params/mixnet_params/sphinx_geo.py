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
COMMAND_TAG_LENGTH = 1  # constants.go:32
NODE_ID_LENGTH = 32  # constants.go:23
SURB_ID_LENGTH = 16  # constants.go:29

# geo_impl.go:211: nextNodeHopLength = CommandTagLength + NodeIDLength + MACLength.
NEXT_NODE_HOP_LENGTH = COMMAND_TAG_LENGTH + NODE_ID_LENGTH + MAC_LENGTH
# geo.go:8: surbReplyLength = CommandTagLength + SURBIDLength.
SURB_REPLY_LENGTH = COMMAND_TAG_LENGTH + SURB_ID_LENGTH

# Default Sphinx UFPL across genconfig + the docker Makefile.
DEFAULT_USER_FORWARD_PAYLOAD_LENGTH = 2000


def per_hop_routing_info_length(kem_ciphertext_bytes: int = None) -> int:
    """Per-hop routing info, from geo_impl.go:158-166's
    ``geometryFactory.perHopRoutingInfoLength``.

    NIKE Sphinx (``kem_ciphertext_bytes=None``): ``nextNodeHopLength +
    surbReplyLength`` -- the next hop's command tag + node ID + MAC, plus the
    SURB-reply command tag + SURB ID. SPRP key material never appears here;
    it appears exactly once, in the SURB itself (see :func:`surb_length`).

    KEM Sphinx (``kem_ciphertext_bytes`` given): the same, plus that hop's
    KEM ciphertext -- the KEM variant carries a fresh ciphertext per hop
    instead of Sphinx's classic re-blinded group element.
    """
    if kem_ciphertext_bytes is None:
        return NEXT_NODE_HOP_LENGTH + SURB_REPLY_LENGTH
    return NEXT_NODE_HOP_LENGTH + SURB_REPLY_LENGTH + kem_ciphertext_bytes


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
