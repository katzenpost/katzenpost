// SPDX-FileCopyrightText: Copyright (C) 2024  David Anthony Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/kem/mkem"
	"github.com/katzenpost/hpqc/nike/schemes"

	"github.com/katzenpost/katzenpost/core/wire/commands"
)

// XXX FIX Test such that we use hpqb/bacap to encrypt the payload
// that way we must also account for the BACAP encryption overhead
// which uses an AEAD known as AES GCM SIV.
func TestReplicaWriteOverhead(t *testing.T) {
	payload := make([]byte, 1000)

	writeCmd := &commands.ReplicaWrite{
		Cmds: nil, // we don't want padding

		BoxID:     &[bacap.BoxIDSize]byte{},
		Signature: &[bacap.SignatureSize]byte{},
		Payload:   payload,
	}
	writeCmdBytes := writeCmd.ToBytes()
	overhead := len(writeCmdBytes) - len(payload)

	geo := NewGeometry(len(payload))
	overhead2 := geo.replicaWriteOverhead()

	t.Logf("writeCmdBytes payload overhead: %d", overhead)
	t.Logf("geo.replicaWriteOverhead: %d", overhead2)

	require.Equal(t, overhead, overhead2)
}

func TestReplicaReadOverhead(t *testing.T) {
	// ReplicaRead only contains a BoxID (Ed25519 public key)
	readCmd := &ReplicaRead{
		BoxID: &[bacap.BoxIDSize]byte{},
	}
	readCmdBytes := readCmd.ToBytes()
	overhead := len(readCmdBytes)

	geo := NewGeometry(1000) // payload size doesn't matter for read overhead
	overhead2 := geo.replicaReadOverhead()

	t.Logf("readCmdBytes overhead: %d", overhead)
	t.Logf("geo.replicaReadOverhead: %d", overhead2)

	require.Equal(t, overhead, overhead2)
}

func TestCourierEnvelopeOverhead(t *testing.T) {
	// Create a CourierEnvelope with fixed payload size
	payload := make([]byte, 1000)

	// Create NIKE scheme for envelope keys
	scheme := schemes.ByName("CTIDH1024-X25519")
	require.NotNil(t, scheme)

	// Generate ephemeral key pair
	ephemeralPub, _, err := scheme.GenerateKeyPair()
	require.NoError(t, err)
	ephemeralPubBytes := ephemeralPub.Bytes()

	envelope := &CourierEnvelope{
		IntermediateReplicas: [2]uint8{0, 1},
		DEK:                  [2]*[mkem.DEKSize]byte{{}, {}},
		ReplyIndex:           0,
		Epoch:                12345,
		SenderEPubKey:        ephemeralPubBytes,
		IsRead:               false,
		Ciphertext:           payload,
	}

	envelopeBytes := envelope.Bytes()
	overhead := len(envelopeBytes) - len(payload)

	geo := NewGeometry(len(payload))
	overhead2 := geo.courierEnvelopeOverhead()

	t.Logf("courierEnvelope overhead: %d", overhead)
	t.Logf("geo.courierEnvelopeOverhead: %d", overhead2)

	require.Equal(t, overhead, overhead2)
}

func TestCourierEnvelopeReplyOverhead(t *testing.T) {
	// Create a CourierEnvelopeReply with fixed payload size
	payload := make([]byte, 1000)

	// Create envelope hash
	envelopeHash := &[hash.HashSize]byte{}

	reply := &CourierEnvelopeReply{
		EnvelopeHash: envelopeHash,
		ReplyIndex:   0,
		ErrorCode:    0,
		Payload:      payload,
	}

	replyBytes := reply.Bytes()
	overhead := len(replyBytes) - len(payload)

	geo := NewGeometry(len(payload))
	overhead2 := geo.courierEnvelopeReplyOverhead()

	t.Logf("geo.courierEnvelopeReplyOverhead: %d", overhead2)

	require.Equal(t, overhead, overhead2)
}

func TestReplicaInnerMessageOverhead(t *testing.T) {
	payload := make([]byte, 1000)
	geo := NewGeometry(len(payload))

	// Test ReplicaRead case
	readMsg := &ReplicaInnerMessage{
		ReplicaRead: &ReplicaRead{
			BoxID: &[bacap.BoxIDSize]byte{},
		},
		ReplicaWrite: nil,
	}
	readMsgBytes := readMsg.Bytes()
	readOverhead := len(readMsgBytes)

	// Test ReplicaWrite case
	writeMsg := &ReplicaInnerMessage{
		ReplicaRead: nil,
		ReplicaWrite: &commands.ReplicaWrite{
			Cmds:      nil, // no padding
			BoxID:     &[bacap.BoxIDSize]byte{},
			Signature: &[bacap.SignatureSize]byte{},
			Payload:   payload,
		},
	}
	writeMsgBytes := writeMsg.Bytes()
	writeOverhead := len(writeMsgBytes) - len(payload)

	// Debug: let's see what the individual components calculate to
	replicaReadOverhead := geo.replicaReadOverhead()
	replicaWriteOverhead := geo.replicaWriteOverhead()

	t.Logf("readOverhead (actual): %d", readOverhead)
	t.Logf("writeOverhead (actual): %d", writeOverhead)
	t.Logf("replicaReadOverhead (calculated): %d", replicaReadOverhead)
	t.Logf("replicaWriteOverhead (calculated): %d", replicaWriteOverhead)

	// The calculated overhead should accommodate both cases
	calculatedOverhead := geo.replicaInnerMessageOverhead()
	t.Logf("calculatedOverhead: %d", calculatedOverhead)

	// The calculated overhead should be at least as large as both actual overheads
	require.GreaterOrEqual(t, calculatedOverhead, readOverhead)
	require.GreaterOrEqual(t, calculatedOverhead, writeOverhead)
}
