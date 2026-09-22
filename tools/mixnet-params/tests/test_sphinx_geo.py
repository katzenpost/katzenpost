# SPDX-FileCopyrightText: (c) 2024 Eva Infeld
# SPDX-License-Identifier: AGPL-3.0-only

"""Verify the Python port of Sphinx geometry against real values observed on
a running mixnet.

The expected numbers below are the ``[SphinxGeometry]`` block namenlos's own
genconfig actually generated (see ``~/namenlos/configs/courier.toml``) for a
5-hop, x25519-NIKE, UFPL=2000 deployment:

    PerHopRoutingInfoLength = 82
    NextNodeHopLength       = 65
    RoutingInfoLength       = 410
    HeaderLength            = 476
    SURBLength              = 572
    SphinxPlaintextHeaderLength = 2
    ForwardPayloadLength    = 2574
    PacketLength            = 3082

This is the same "pin to real running-config output" discipline
``tests/test_pigeonhole_geo.py`` already uses for the pigeonhole side.
"""

from mixnet_params.sphinx_geo import (
    AD_LENGTH,
    MAC_LENGTH,
    NEXT_NODE_HOP_LENGTH,
    PAYLOAD_TAG_LENGTH,
    SPHINX_PLAINTEXT_HEADER_LENGTH,
    SPRP_KEY_MATERIAL_LENGTH,
    SURB_REPLY_LENGTH,
    derive_forward_payload_length,
    header_length,
    packet_length,
    per_hop_routing_info_length,
    routing_info_length,
    surb_length,
)


X25519_PUBKEY_BYTES = 32
NAMENLOS_HOPS = 5
NAMENLOS_UFPL = 2000


def test_next_node_hop_length():
    # CommandTagLength(1) + NodeIDLength(32) + MACLength(32).
    assert NEXT_NODE_HOP_LENGTH == 65


def test_surb_reply_length():
    # CommandTagLength(1) + SURBIDLength(16).
    assert SURB_REPLY_LENGTH == 17


def test_per_hop_routing_info_length_nike_matches_namenlos():
    # namenlos courier.toml: PerHopRoutingInfoLength = 82.
    assert per_hop_routing_info_length() == 82


def test_per_hop_routing_info_length_kem_adds_ciphertext():
    # Illustrative only (namenlos runs NIKE Sphinx, not KEM Sphinx): a KEM
    # variant's per-hop routing info additionally carries that hop's KEM
    # ciphertext instead of relying on a re-blinded group element.
    illustrative_kem_ciphertext_bytes = 1088
    assert (
        per_hop_routing_info_length(illustrative_kem_ciphertext_bytes)
        == 82 + illustrative_kem_ciphertext_bytes
    )


def test_routing_info_length_matches_namenlos():
    one_hop = per_hop_routing_info_length()
    # namenlos courier.toml: RoutingInfoLength = 410 = 82 * 5.
    assert routing_info_length(NAMENLOS_HOPS, one_hop) == 410


def test_header_length_matches_namenlos():
    one_hop = per_hop_routing_info_length()
    routing_info = routing_info_length(NAMENLOS_HOPS, one_hop)
    # namenlos courier.toml: HeaderLength = 476 = 2 + 32 + 410 + 32.
    assert header_length(X25519_PUBKEY_BYTES, routing_info) == 476
    assert AD_LENGTH + X25519_PUBKEY_BYTES + routing_info + MAC_LENGTH == 476


def test_surb_length_matches_namenlos():
    hdr = header_length(
        X25519_PUBKEY_BYTES,
        routing_info_length(NAMENLOS_HOPS, per_hop_routing_info_length()),
    )
    # namenlos courier.toml: SURBLength = 572 = 476 + 32 + 64.
    assert surb_length(hdr) == 572
    assert hdr + 32 + SPRP_KEY_MATERIAL_LENGTH == 572


def test_derive_forward_payload_length_matches_namenlos():
    hdr = header_length(
        X25519_PUBKEY_BYTES,
        routing_info_length(NAMENLOS_HOPS, per_hop_routing_info_length()),
    )
    surb = surb_length(hdr)
    # namenlos courier.toml: ForwardPayloadLength = 2574 = 2000 + 2 + 572.
    assert derive_forward_payload_length(NAMENLOS_UFPL, surb) == 2574
    assert NAMENLOS_UFPL + SPHINX_PLAINTEXT_HEADER_LENGTH + surb == 2574


def test_packet_length_matches_namenlos():
    hdr = header_length(
        X25519_PUBKEY_BYTES,
        routing_info_length(NAMENLOS_HOPS, per_hop_routing_info_length()),
    )
    surb = surb_length(hdr)
    fwd = derive_forward_payload_length(NAMENLOS_UFPL, surb)
    # namenlos courier.toml: PacketLength = 3082 = 476 + 32 + 2574.
    assert packet_length(hdr, fwd) == 3082
    assert hdr + PAYLOAD_TAG_LENGTH + fwd == 3082
