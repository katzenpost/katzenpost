// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/kem/mkem"
	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/hpqc/sign/ed25519"

	"github.com/katzenpost/katzenpost/core/wire/commands"
	"github.com/katzenpost/katzenpost/pigeonhole"
	replicaCommon "github.com/katzenpost/katzenpost/replica/common"
)

type replicatingConnector struct {
	*mockConnector
	mu     sync.Mutex
	writes []*commands.ReplicaWrite
}

func (c *replicatingConnector) DispatchReplication(cmd *commands.ReplicaWrite) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes = append(c.writes, cmd)
}

func (c *replicatingConnector) replicated() []*commands.ReplicaWrite {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]*commands.ReplicaWrite(nil), c.writes...)
}

// storeTestBox stores a signed box and returns it.
func storeTestBox(t *testing.T, env *semaScopeTestEnv) *commands.ReplicaWrite {
	t.Helper()
	s := ed25519.Scheme()
	pub, priv, err := s.GenerateKey()
	require.NoError(t, err)
	pubBytes, err := pub.MarshalBinary()
	require.NoError(t, err)
	var boxID [32]byte
	copy(boxID[:], pubBytes)
	payload := make([]byte, env.server.pigeonholeGeo.CalculateBoxCiphertextLength())
	_, err = rand.Reader.Read(payload)
	require.NoError(t, err)
	var sig [64]byte
	copy(sig[:], s.Sign(priv, payload, nil))
	write := &commands.ReplicaWrite{BoxID: &boxID, Signature: &sig, Payload: payload}
	require.NoError(t, env.server.state.handleReplicaWrite(write))
	return write
}

// readReplicaMessage encapsulates a read of boxID to the server's
// current envelope key.
func readReplicaMessage(t *testing.T, env *semaScopeTestEnv, boxID *[32]byte) *commands.ReplicaMessage {
	t.Helper()
	inner := &pigeonhole.ReplicaInnerMessage{
		MessageType: 0,
		ReadMsg:     &pigeonhole.ReplicaRead{BoxID: *boxID},
	}
	padded, err := pigeonhole.PadInnerMessageForEncryption(inner, env.server.pigeonholeGeo)
	require.NoError(t, err)
	replicaEpoch, _, _ := replicaCommon.ReplicaNow()
	keypair, err := env.server.envelopeKeys.GetKeypair(replicaEpoch)
	require.NoError(t, err)
	_, ct, err := replicaCommon.MKEMNikeScheme.Encapsulate([]nike.PublicKey{keypair.PublicKey}, padded)
	require.NoError(t, err)
	return &commands.ReplicaMessage{
		Cmds:               commands.NewStorageReplicaCommands(env.server.cfg.SphinxGeometry, replicaCommon.NikeScheme),
		PigeonholeGeometry: env.server.pigeonholeGeo,
		Scheme:             replicaCommon.NikeScheme,
		SenderEPubKey:      ct.EphemeralPublicKey.Bytes(),
		DEK:                (*[mkem.DEKSize]byte)(ct.DEKCiphertexts[0]),
		Ciphertext:         ct.Envelope,
	}
}

func repairHint(envHash *[32]byte) *commands.ReplicaDecoy {
	return &commands.ReplicaDecoy{RepairEnvelopeHash: envHash}
}

// TestRepairHintReplicatesServedBox serves a read, then receives the
// courier's repair hint for it, and replicates the box it read once.
func TestRepairHintReplicatesServedBox(t *testing.T) {
	env := setupSemaScopeTestServer(t)
	cc := &replicatingConnector{mockConnector: newMockConnector(env.server)}
	env.server.connector = cc

	box := storeTestBox(t, env)
	read := readReplicaMessage(t, env, box.BoxID)
	reply := env.inConn.handleReplicaMessage(read, func() {})
	require.Equal(t, pigeonhole.ReplicaSuccess, reply.ErrorCode)
	require.Empty(t, cc.replicated(), "a served read replicated before any hint")

	resp, ok := env.inConn.onReplicaCommand(repairHint(read.EnvelopeHash()), env.emitter)
	require.True(t, ok)
	require.NotNil(t, resp.ReplicaDecoy, "a repair hint must be answered like a decoy")

	writes := cc.replicated()
	require.Len(t, writes, 1)
	require.Equal(t, box.BoxID, writes[0].BoxID)
	require.Equal(t, box.Signature, writes[0].Signature)
	require.Equal(t, box.Payload, writes[0].Payload)

	env.inConn.onReplicaCommand(repairHint(read.EnvelopeHash()), env.emitter)
	require.Len(t, cc.replicated(), 1, "a second hint for the same read replicated again")
}

// TestRepairHintIgnoresUnservedReads ignores hints for a read that found
// nothing and for an envelope this replica never served.
func TestRepairHintIgnoresUnservedReads(t *testing.T) {
	env := setupSemaScopeTestServer(t)
	cc := &replicatingConnector{mockConnector: newMockConnector(env.server)}
	env.server.connector = cc

	missing := &[32]byte{7}
	read := readReplicaMessage(t, env, missing)
	reply := env.inConn.handleReplicaMessage(read, func() {})
	require.Equal(t, pigeonhole.ReplicaErrorBoxIDNotFound, reply.ErrorCode)

	env.inConn.onReplicaCommand(repairHint(read.EnvelopeHash()), env.emitter)
	env.inConn.onReplicaCommand(repairHint(&[32]byte{9}), env.emitter)
	require.Empty(t, cc.replicated())
}

func TestReadRepairsForgetOldest(t *testing.T) {
	var r readRepairs
	now := time.Now()
	for i := 0; i < maxReadRepairs+1; i++ {
		var h [32]byte
		h[0], h[1] = byte(i), byte(i>>8)
		r.remember(&h, &h, now)
	}
	require.Len(t, r.boxes, maxReadRepairs)
	_, ok := r.take(&[32]byte{0, 0}, now)
	require.False(t, ok, "the oldest read was not forgotten at the bound")
	n := maxReadRepairs
	last := [32]byte{byte(n), byte(n >> 8)}
	got, ok := r.take(&last, now)
	require.True(t, ok)
	require.Equal(t, last, got)

	h := [32]byte{1, 2, 3}
	r.remember(&h, &h, now)
	_, ok = r.take(&h, now.Add(readRepairTTL+time.Second))
	require.False(t, ok, "an expired read was repaired")
}
