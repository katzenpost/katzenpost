# SPDX-FileCopyrightText: (c) 2024 Eva Infeld
# SPDX-License-Identifier: AGPL-3.0-only

"""Verify the Python port of Sphinx geometry against the formulas in
core/sphinx/geo/geo.go.

The header_length and packet_length helpers are exercised with x25519
(32-byte pubkey, the docker-mixnet Sphinx NIKE) and a 5-hop topology
to give round numbers a reviewer can verify by reading the Go source.
"""

from mixnet_params.sphinx_geo import (
    AD_LENGTH,
    MAC_LENGTH,
    PAYLOAD_TAG_LENGTH,
    SPHINX_PLAINTEXT_HEADER_LENGTH,
    SPRP_KEY_MATERIAL_LENGTH,
    derive_forward_payload_length,
    header_length,
    packet_length,
    per_hop_routing_info_length,
    routing_info_length,
    surb_length,
)


X25519_PUBKEY_BYTES = 32


def test_per_hop_routing_info_length():
    # CommandTagLength (1) + NodeIDLength (32) + MACLength (32) +
    # SPRPKeyMaterialLength (64) = 129
    assert per_hop_routing_info_length() == 129


def test_routing_info_length_scales_linearly():
    one_hop = per_hop_routing_info_length()
    assert routing_info_length(1, one_hop) == one_hop
    assert routing_info_length(5, one_hop) == 5 * one_hop


def test_header_length_x25519_5hops():
    # adLength + pubkey + 5*per_hop + MACLength
    one_hop = per_hop_routing_info_length()
    expected = AD_LENGTH + X25519_PUBKEY_BYTES + 5 * one_hop + MAC_LENGTH
    assert header_length(X25519_PUBKEY_BYTES, routing_info_length(5, one_hop)) == expected


def test_surb_length_carries_full_header_plus_node_and_keymat():
    hdr = header_length(X25519_PUBKEY_BYTES, routing_info_length(5, per_hop_routing_info_length()))
    # surb = header + NodeIDLength(32) + sprp_key_material(64)
    assert surb_length(hdr) == hdr + 32 + SPRP_KEY_MATERIAL_LENGTH


def test_packet_length_assembles_header_tag_and_payload():
    hdr = header_length(X25519_PUBKEY_BYTES, routing_info_length(5, per_hop_routing_info_length()))
    fwd = 2000
    assert packet_length(hdr, fwd) == hdr + PAYLOAD_TAG_LENGTH + fwd


def test_derive_forward_payload_length_with_surb():
    hdr = header_length(X25519_PUBKEY_BYTES, routing_info_length(5, per_hop_routing_info_length()))
    surb = surb_length(hdr)
    ufpl = 2000
    # geo.go:264: ufpl + sphinx_plaintext_header + surb
    assert derive_forward_payload_length(ufpl, surb) == ufpl + SPHINX_PLAINTEXT_HEADER_LENGTH + surb
