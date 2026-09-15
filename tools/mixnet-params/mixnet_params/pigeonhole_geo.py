# SPDX-FileCopyrightText: (c) 2024 Eva Infeld
# SPDX-License-Identifier: AGPL-3.0-only

"""Pigeonhole geometry arithmetic.

Pure-function port of ``NewGeometryFromSphinx`` and its named
overheads from ``pigeonhole/geo/geometry.go`` (katzenpost monorepo).
Given a Sphinx ``UserForwardPayloadLength`` and the public-key size of
the NIKE scheme the replicas use for MKEM (CTIDH1024-X25519 on the
docker mixnet, but the calculator accepts any NIKE pubkey size), this
module returns the per-Sphinx-packet useful payload after every
wrapper has taken its bite.

The "useful payload" is the BACAP-plaintext box-content max:
the bytes a thin client can encrypt into a single pigeonhole write
before the message is chunked. The CTIDH cost on the replica side is
paid once per Sphinx packet, so this number is the divisor that turns
the replica's MKEM-ops-per-second ceiling into a useful-bytes-per-
second ceiling.
"""

# Wrapper overheads from pigeonhole/geo/geometry.go.
BACAP_ENCRYPTION_OVERHEAD = 16  # geometry.go:54
LENGTH_PREFIX_SIZE = 4  # geometry.go:57
# chacha20poly1305: 12-byte nonce + 16-byte AEAD tag.
MKEM_ENCRYPTION_OVERHEAD = 12 + 16  # geometry.go:60
MESSAGE_TYPE_SIZE = 1  # geometry.go:66
QUERY_TYPE_SIZE = 1  # geometry.go:97

# CourierEnvelope fixed fields from the trunnel definition
# (geometry.go:91-94, 105-111).
INTERMEDIATE_REPLICAS_SIZE = 2  # [2]uint8
REPLY_INDEX_SIZE = 1  # uint8
EPOCH_SIZE = 8  # uint64
SENDER_PUBKEY_LEN_SIZE = 2  # uint16
CIPHERTEXT_LEN_FIELD_SIZE = 4  # uint32
DEK_SIZE = 60  # hpqc/kem/mkem/mkem.go:23
PAYLOAD_LEN_FIELD_SIZE = 4  # geometry.go:75

# BACAP sizes from hpqc/bacap/bacap.go:87,90 (alias ed25519's).
BACAP_BOX_ID_SIZE = 32  # ed25519.PublicKeySize
BACAP_SIGNATURE_SIZE = 64  # ed25519.SignatureSize

# Default replica NIKE: CTIDH1024-X25519 hybrid, used by the docker
# mixnet's replicas as the MKEM scheme. CTIDH1024 pubkey is 128 bytes
# (codeberg.org/vula/highctidh/.../ctidh1024.go:290); X25519 is 32
# (hpqc/nike/x25519/ecdh.go:20). Hybrid pubkey is the sum.
DEFAULT_REPLICA_NIKE_PUBKEY_SIZE = 128 + 32


def replica_write_fixed_overhead() -> int:
    """`replicaWriteFixedOverhead` from geometry.go:101: a BACAP box
    write carries the box ID, the ed25519 signature, and the
    payload-length field."""
    return BACAP_BOX_ID_SIZE + BACAP_SIGNATURE_SIZE + PAYLOAD_LEN_FIELD_SIZE


def calculate_courier_envelope_overhead(sender_pubkey_size: int) -> int:
    """`calculateCourierEnvelopeOverhead` from geometry.go:106: the
    trunnel-fixed fields of a ``CourierEnvelope`` plus the sender's
    NIKE public key for the MKEM encapsulation."""
    fixed = (
        INTERMEDIATE_REPLICAS_SIZE
        + 2 * DEK_SIZE
        + REPLY_INDEX_SIZE
        + EPOCH_SIZE
        + SENDER_PUBKEY_LEN_SIZE
        + CIPHERTEXT_LEN_FIELD_SIZE
    )
    return fixed + sender_pubkey_size


def total_wrapper_overhead(sender_pubkey_size: int) -> int:
    """Sum of every wrapper layer between the Sphinx
    UserForwardPayload (outer) and the BACAP plaintext (inner).
    Mirrors the additions on geometry.go:182-185 verbatim."""
    courier_query_overhead = QUERY_TYPE_SIZE
    courier_envelope_overhead = calculate_courier_envelope_overhead(sender_pubkey_size)
    mkem_overhead = MKEM_ENCRYPTION_OVERHEAD
    replica_inner_message_overhead = MESSAGE_TYPE_SIZE
    replica_write_overhead = replica_write_fixed_overhead()
    bacap_overhead = BACAP_ENCRYPTION_OVERHEAD
    length_prefix_overhead = LENGTH_PREFIX_SIZE
    trunnel_length_prefix_overhead = LENGTH_PREFIX_SIZE
    return (
        courier_query_overhead
        + courier_envelope_overhead
        + mkem_overhead
        + replica_inner_message_overhead
        + replica_write_overhead
        + bacap_overhead
        + length_prefix_overhead
        + trunnel_length_prefix_overhead
    )


def max_plaintext_payload_from_ufpl(
    ufpl: int,
    sender_pubkey_size: int = DEFAULT_REPLICA_NIKE_PUBKEY_SIZE,
) -> int:
    """`NewGeometryFromSphinx` from geometry.go:148: given a Sphinx
    UFPL and the MKEM sender-pubkey size, return
    ``MaxPlaintextPayloadLength`` (the box-content cap a client can
    encrypt into a single Sphinx packet).

    Raises ``ValueError`` if UFPL is too small to accommodate the
    wrappers, mirroring the Go-side error at geometry.go:191.
    """
    total_overhead = total_wrapper_overhead(sender_pubkey_size)
    box_payload = ufpl - total_overhead
    if box_payload <= 0:
        raise ValueError(
            f"sphinx geometry too small: UserForwardPayloadLength={ufpl}, "
            f"total overhead={total_overhead}"
        )
    return box_payload


# Pigeonhole-cp has TWO levels of chunking, both implemented in
# client/pigeonhole.go's createCourierEnvelopesFromPayload (line 530)
# and pigeonhole/copy_stream.go's CopyStreamEncoder (line 50). The
# user-payload is first sliced into BACAP-encrypted CourierEnvelopes,
# then those envelopes are length-prefixed, concatenated, and
# re-sliced into copy-stream elements that the daemon writes to the
# temp-stream boxes one element per StartResendingEncryptedMessage
# call.
#
# Level 1: validateEnvelopePayloadRequest (client/pigeonhole.go:413)
# rejects payloads where MaxPlaintextPayloadLength - 4 is non-positive,
# and chunkPayload (client/pigeonhole.go:385) splits the user payload
# into BACAP-plaintext-sized pieces. Each piece carries a 4-byte
# length prefix and becomes the plaintext of one CourierEnvelope.
#
# Level 2: NewCopyStreamEncoder (pigeonhole/copy_stream.go:50) wraps
# each envelope with a 4-byte length prefix, concatenates into a
# buffer, and emits elements of size
# (MaxPlaintextPayloadLength - CopyStreamElementOverhead) where
# CopyStreamElementOverhead = 5 (1 byte flags + 4 byte envelope_len).
# Plus the encoder always leaves at least one chunk's worth in the
# buffer so Flush() can set the IsFinal flag on the last element.
#
# An envelope, when marshalled, is exactly Sphinx UFPL bytes (the
# Sphinx geometry is the constraint that fixes envelope size).

CHUNK_LENGTH_PREFIX = 4
COPY_STREAM_ELEMENT_OVERHEAD = 5  # copy_stream.go:22
ENVELOPE_LENGTH_PREFIX = 4  # copy_stream.go:94


def envelope_capacity_bytes(max_plaintext_payload: int) -> int:
    """Bytes of user payload one ``CourierEnvelope`` carries: the box
    plaintext less the 4-byte length-prefix the envelope construction
    adds. Matches ``maxPayload`` in
    client/pigeonhole.go:530."""
    cap_ = max_plaintext_payload - CHUNK_LENGTH_PREFIX
    if cap_ <= 0:
        raise ValueError(
            "max_plaintext_payload too small for the 4-byte chunk prefix"
        )
    return cap_


def envelopes_required(payload_bytes: int, envelope_capacity: int) -> int:
    """How many CourierEnvelopes ``chunkPayload`` will emit for the
    given user payload."""
    if payload_bytes <= 0:
        return 0
    return (payload_bytes + envelope_capacity - 1) // envelope_capacity


def copy_stream_element_capacity_bytes(max_plaintext_payload: int) -> int:
    """The ``maxChunkSize`` the copy-stream encoder uses for one
    element. Matches copy_stream.go:53."""
    cap_ = max_plaintext_payload - COPY_STREAM_ELEMENT_OVERHEAD
    if cap_ <= 0:
        raise ValueError(
            "max_plaintext_payload too small for the 5-byte copy-stream overhead"
        )
    return cap_


def copy_stream_elements_required(
    payload_bytes: int,
    max_plaintext_payload: int,
    ufpl: int,
) -> int:
    """How many copy-stream elements ``CreateCourierEnvelopesFromPayload``
    will emit for the given user payload.

    Models the full two-level chunking faithfully:

      1. Split the user payload into ``envelopes_required`` BACAP-sized
         pieces (one CourierEnvelope each).
      2. Concatenate each envelope's 4-byte length prefix and bytes
         into the encoder buffer.
      3. Emit ``ceil(buffer_size / copy_stream_element_capacity)``
         elements.

    Each marshalled envelope is exactly ``ufpl`` bytes (the Sphinx
    geometry is the constraint that fixes envelope size; see the
    ``CourierQueryWriteLength`` value in the generated client config
    on a running mixnet).
    """
    if payload_bytes <= 0:
        return 0
    env_cap = envelope_capacity_bytes(max_plaintext_payload)
    num_envelopes = envelopes_required(payload_bytes, env_cap)
    buffer_bytes = num_envelopes * (ENVELOPE_LENGTH_PREFIX + ufpl)
    elem_cap = copy_stream_element_capacity_bytes(max_plaintext_payload)
    return (buffer_bytes + elem_cap - 1) // elem_cap


# Backwards-compat aliases. The historical name ``chunks_required``
# meant copy-stream elements; preserve it as a passthrough so older
# callers keep working without learning the two-level distinction.
def chunk_capacity_bytes(max_plaintext_payload: int) -> int:
    """Deprecated; use :func:`envelope_capacity_bytes` if you want
    BACAP-level capacity or :func:`copy_stream_element_capacity_bytes`
    for the post-encoder element capacity. Kept as an alias of the
    BACAP-level capacity for compatibility."""
    return envelope_capacity_bytes(max_plaintext_payload)


def chunks_required(payload_bytes: int, max_plaintext_payload: int, ufpl: int) -> int:
    """Returns the copy-stream element count, the same number
    ``CreateCourierEnvelopesFromPayload`` returns from a thin client.
    Operators usually want this one, not the BACAP-level envelope
    count."""
    return copy_stream_elements_required(payload_bytes, max_plaintext_payload, ufpl)
