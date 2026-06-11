// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package pigeonhole

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestTrunnelRoundTrip exercises the property that for every trunnel-defined
// struct in this package, serialising via .Bytes() and parsing the result
// via ParseFoo yields an instance whose own .Bytes() is byte-identical to
// the original. This catches asymmetries between the Parse and encodeBinary
// paths, which the per-fixture corpus tests do not cover (they only
// parse). Each union type is exercised for every defined tag so that no
// case-branch silently drops a field on encode or parse.
func TestTrunnelRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		// run takes the test instance, marshals, parses, marshals
		// again, and asserts the two byte strings are identical.
		run func(t *testing.T)
	}{
		{
			name: "CourierEnvelope",
			run: func(t *testing.T) {
				orig := buildCourierEnvelope()
				assertRoundTrip(t, orig.Bytes(), func(b []byte) ([]byte, error) {
					p, err := ParseCourierEnvelope(b)
					if err != nil {
						return nil, err
					}
					return p.Bytes(), nil
				})
			},
		},
		{
			name: "CourierEnvelopeReply_ACK",
			run: func(t *testing.T) {
				orig := buildCourierEnvelopeReply(0, nil)
				assertRoundTrip(t, orig.Bytes(), func(b []byte) ([]byte, error) {
					p, err := ParseCourierEnvelopeReply(b)
					if err != nil {
						return nil, err
					}
					return p.Bytes(), nil
				})
			},
		},
		{
			name: "CourierEnvelopeReply_PAYLOAD",
			run: func(t *testing.T) {
				orig := buildCourierEnvelopeReply(1, []byte("hello"))
				assertRoundTrip(t, orig.Bytes(), func(b []byte) ([]byte, error) {
					p, err := ParseCourierEnvelopeReply(b)
					if err != nil {
						return nil, err
					}
					return p.Bytes(), nil
				})
			},
		},
		{
			name: "CourierQuery_envelope",
			run: func(t *testing.T) {
				orig := &CourierQuery{
					QueryType: 0,
					Envelope:  buildCourierEnvelope(),
				}
				assertRoundTrip(t, orig.Bytes(), func(b []byte) ([]byte, error) {
					p, err := ParseCourierQuery(b)
					if err != nil {
						return nil, err
					}
					return p.Bytes(), nil
				})
			},
		},
		{
			name: "CourierQuery_copy_command",
			run: func(t *testing.T) {
				orig := &CourierQuery{
					QueryType:   1,
					CopyCommand: buildCopyCommand(),
				}
				assertRoundTrip(t, orig.Bytes(), func(b []byte) ([]byte, error) {
					p, err := ParseCourierQuery(b)
					if err != nil {
						return nil, err
					}
					return p.Bytes(), nil
				})
			},
		},
		{
			name: "CourierQueryReply_envelope_reply",
			run: func(t *testing.T) {
				orig := &CourierQueryReply{
					ReplyType:     0,
					EnvelopeReply: buildCourierEnvelopeReply(0, nil),
				}
				assertRoundTrip(t, orig.Bytes(), func(b []byte) ([]byte, error) {
					p, err := ParseCourierQueryReply(b)
					if err != nil {
						return nil, err
					}
					return p.Bytes(), nil
				})
			},
		},
		{
			name: "CourierQueryReply_copy_command_reply",
			run: func(t *testing.T) {
				orig := &CourierQueryReply{
					ReplyType: 1,
					CopyCommandReply: &CopyCommandReply{
						Status:              1,
						ErrorCode:           0,
						FailedEnvelopeIndex: 0,
					},
				}
				assertRoundTrip(t, orig.Bytes(), func(b []byte) ([]byte, error) {
					p, err := ParseCourierQueryReply(b)
					if err != nil {
						return nil, err
					}
					return p.Bytes(), nil
				})
			},
		},
		{
			name: "ReplicaRead",
			run: func(t *testing.T) {
				orig := &ReplicaRead{}
				for i := range orig.BoxID {
					orig.BoxID[i] = byte(i)
				}
				assertRoundTrip(t, orig.Bytes(), func(b []byte) ([]byte, error) {
					p, err := ParseReplicaRead(b)
					if err != nil {
						return nil, err
					}
					return p.Bytes(), nil
				})
			},
		},
		{
			name: "ReplicaReadReply",
			run: func(t *testing.T) {
				orig := buildReplicaReadReply()
				assertRoundTrip(t, orig.Bytes(), func(b []byte) ([]byte, error) {
					p, err := ParseReplicaReadReply(b)
					if err != nil {
						return nil, err
					}
					return p.Bytes(), nil
				})
			},
		},
		{
			name: "ReplicaWrite",
			run: func(t *testing.T) {
				orig := buildReplicaWrite()
				assertRoundTrip(t, orig.Bytes(), func(b []byte) ([]byte, error) {
					p, err := ParseReplicaWrite(b)
					if err != nil {
						return nil, err
					}
					return p.Bytes(), nil
				})
			},
		},
		{
			name: "ReplicaWriteReply",
			run: func(t *testing.T) {
				orig := &ReplicaWriteReply{ErrorCode: 0}
				assertRoundTrip(t, orig.Bytes(), func(b []byte) ([]byte, error) {
					p, err := ParseReplicaWriteReply(b)
					if err != nil {
						return nil, err
					}
					return p.Bytes(), nil
				})
			},
		},
		{
			name: "ReplicaInnerMessage_read",
			run: func(t *testing.T) {
				readMsg := &ReplicaRead{}
				for i := range readMsg.BoxID {
					readMsg.BoxID[i] = byte(i)
				}
				orig := &ReplicaInnerMessage{
					MessageType: 0,
					ReadMsg:     readMsg,
				}
				assertRoundTrip(t, orig.Bytes(), func(b []byte) ([]byte, error) {
					p, err := ParseReplicaInnerMessage(b)
					if err != nil {
						return nil, err
					}
					return p.Bytes(), nil
				})
			},
		},
		{
			name: "ReplicaInnerMessage_write",
			run: func(t *testing.T) {
				orig := &ReplicaInnerMessage{
					MessageType: 1,
					WriteMsg:    buildReplicaWrite(),
				}
				assertRoundTrip(t, orig.Bytes(), func(b []byte) ([]byte, error) {
					p, err := ParseReplicaInnerMessage(b)
					if err != nil {
						return nil, err
					}
					return p.Bytes(), nil
				})
			},
		},
		{
			name: "ReplicaMessageReplyInnerMessage_read",
			run: func(t *testing.T) {
				orig := &ReplicaMessageReplyInnerMessage{
					MessageType: 0,
					ReadReply:   buildReplicaReadReply(),
				}
				assertRoundTrip(t, orig.Bytes(), func(b []byte) ([]byte, error) {
					p, err := ParseReplicaMessageReplyInnerMessage(b)
					if err != nil {
						return nil, err
					}
					return p.Bytes(), nil
				})
			},
		},
		{
			name: "ReplicaMessageReplyInnerMessage_write",
			run: func(t *testing.T) {
				orig := &ReplicaMessageReplyInnerMessage{
					MessageType: 1,
					WriteReply:  &ReplicaWriteReply{ErrorCode: 0},
				}
				assertRoundTrip(t, orig.Bytes(), func(b []byte) ([]byte, error) {
					p, err := ParseReplicaMessageReplyInnerMessage(b)
					if err != nil {
						return nil, err
					}
					return p.Bytes(), nil
				})
			},
		},
		{
			name: "Box",
			run: func(t *testing.T) {
				orig := buildBox()
				assertRoundTrip(t, orig.Bytes(), func(b []byte) ([]byte, error) {
					p, err := ParseBox(b)
					if err != nil {
						return nil, err
					}
					return p.Bytes(), nil
				})
			},
		},
		{
			name: "CopyCommand",
			run: func(t *testing.T) {
				assertRoundTrip(t, mustMarshal(t, buildCopyCommand()), func(b []byte) ([]byte, error) {
					p, err := ParseCopyCommand(b)
					if err != nil {
						return nil, err
					}
					return p.MarshalBinary()
				})
			},
		},
		{
			name: "CopyCommandReply",
			run: func(t *testing.T) {
				orig := &CopyCommandReply{
					Status:              2,
					ErrorCode:           7,
					FailedEnvelopeIndex: 42,
				}
				assertRoundTrip(t, mustMarshal(t, orig), func(b []byte) ([]byte, error) {
					p, err := ParseCopyCommandReply(b)
					if err != nil {
						return nil, err
					}
					return p.MarshalBinary()
				})
			},
		},
		{
			name: "CopyStreamElement",
			run: func(t *testing.T) {
				orig := &CopyStreamElement{
					Flags:        0x03,
					EnvelopeLen:  4,
					EnvelopeData: []byte{0xde, 0xad, 0xbe, 0xef},
				}
				assertRoundTrip(t, mustMarshal(t, orig), func(b []byte) ([]byte, error) {
					p, err := ParseCopyStreamElement(b)
					if err != nil {
						return nil, err
					}
					return p.MarshalBinary()
				})
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, tc.run)
	}
}

// assertRoundTrip parses the supplied encoding via the caller-supplied
// re-encode closure (which performs Parse-then-encode) and asserts the
// result is byte-identical to the input. The closure shape lets each
// test case carry its own ParseFoo without a type switch.
func assertRoundTrip(t *testing.T, encoded []byte, reEncode func([]byte) ([]byte, error)) {
	t.Helper()
	again, err := reEncode(encoded)
	require.NoError(t, err)
	require.Equal(t, encoded, again, "round-tripped encoding differs from original")
}

// mustMarshal serializes via MarshalBinary and fails the test on error.
// Used for trunnel types that lack the Bytes() helper but always succeed
// on valid input.
func mustMarshal(t *testing.T, m interface{ MarshalBinary() ([]byte, error) }) []byte {
	t.Helper()
	b, err := m.MarshalBinary()
	require.NoError(t, err)
	return b
}

func buildCourierEnvelope() *CourierEnvelope {
	pubkey := make([]byte, 32)
	for i := range pubkey {
		pubkey[i] = byte(i)
	}
	ct := make([]byte, 16)
	for i := range ct {
		ct[i] = 0x80 ^ byte(i)
	}
	return &CourierEnvelope{
		IntermediateReplicas: [2]uint8{3, 7},
		Dek1:                 [60]uint8{},
		Dek2:                 [60]uint8{},
		ReplyIndex:           1,
		Epoch:                987654321,
		SenderPubkeyLen:      uint16(len(pubkey)),
		SenderPubkey:         pubkey,
		CiphertextLen:        uint32(len(ct)),
		Ciphertext:           ct,
	}
}

func buildCourierEnvelopeReply(replyType uint8, payload []byte) *CourierEnvelopeReply {
	r := &CourierEnvelopeReply{
		ReplyIndex: 0,
		ReplyType:  replyType,
		ErrorCode:  0,
	}
	for i := range r.EnvelopeHash {
		r.EnvelopeHash[i] = byte(i + 1)
	}
	if replyType == 1 && payload != nil {
		r.PayloadLen = uint32(len(payload))
		r.Payload = payload
	}
	return r
}

func buildReplicaWrite() *ReplicaWrite {
	w := &ReplicaWrite{
		PayloadLen: 8,
		Payload:    []byte{1, 2, 3, 4, 5, 6, 7, 8},
	}
	for i := range w.BoxID {
		w.BoxID[i] = byte(i)
	}
	for i := range w.Signature {
		w.Signature[i] = byte(0xff - i)
	}
	return w
}

func buildReplicaReadReply() *ReplicaReadReply {
	r := &ReplicaReadReply{
		ErrorCode:  0,
		PayloadLen: 4,
		Payload:    []byte{0x11, 0x22, 0x33, 0x44},
	}
	for i := range r.BoxID {
		r.BoxID[i] = byte(i)
	}
	for i := range r.Signature {
		r.Signature[i] = byte(i * 2)
	}
	return r
}

func buildBox() *Box {
	b := &Box{
		PayloadLen: 6,
		Payload:    []byte{0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6},
	}
	for i := range b.BoxID {
		b.BoxID[i] = byte(i)
	}
	for i := range b.Signature {
		b.Signature[i] = byte(0x10 + i)
	}
	return b
}

func buildCopyCommand() *CopyCommand {
	cap := []byte("test-write-capability-bytes")
	return &CopyCommand{
		WriteCapLen: uint32(len(cap)),
		WriteCap:    cap,
	}
}
