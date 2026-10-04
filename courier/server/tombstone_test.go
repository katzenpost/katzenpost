// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/hpqc/sign/ed25519"

	"github.com/katzenpost/katzenpost/client/constants"
	"github.com/katzenpost/katzenpost/pigeonhole"
	pgeo "github.com/katzenpost/katzenpost/pigeonhole/geo"
)

// The courier deletes the copy stream's temp boxes with tempTombstone. A
// replica stores a write as a tombstone only when its payload is empty and
// its signature verifies over the empty payload under the box ID
// (replica/handlers.go); anything else is an ordinary write, which an
// existing box refuses.
func TestTempTombstoneIsATombstone(t *testing.T) {
	wc, err := bacap.NewWriteCap(rand.Reader)
	require.NoError(t, err)
	idx := wc.GetMessageBoxIndex()

	write, next, err := tempTombstone(wc, idx)
	require.NoError(t, err)

	box, err := idx.BoxIDForContext(wc.ReadCap(), constants.PIGEONHOLE_CTX)
	require.NoError(t, err)
	require.Equal(t, box.Bytes(), write.BoxID[:], "the tombstone is for the box at idx")

	require.Zero(t, write.PayloadLen)
	require.Empty(t, write.Payload)
	s := ed25519.Scheme()
	key, err := s.UnmarshalBinaryPublicKey(write.BoxID[:])
	require.NoError(t, err)
	require.True(t, s.Verify(key, []byte{}, write.Signature[:], nil), "signed over the empty payload")

	want, err := idx.NextIndex()
	require.NoError(t, err)
	require.Equal(t, want, next)
}

// A tombstone travels as long as any other write: the inner message is
// padded to a fixed size before it is encrypted to the replicas.
func TestTempTombstonePadsLikeAWrite(t *testing.T) {
	geo := pgeo.NewGeometry(1530, schemes.ByName("x25519"))
	wc, err := bacap.NewWriteCap(rand.Reader)
	require.NoError(t, err)
	idx := wc.GetMessageBoxIndex()

	tomb, _, err := tempTombstone(wc, idx)
	require.NoError(t, err)
	paddedTomb, err := pigeonhole.PadInnerMessageForEncryption(
		&pigeonhole.ReplicaInnerMessage{MessageType: 1, WriteMsg: tomb}, geo)
	require.NoError(t, err)

	padded, err := pigeonhole.CreatePaddedPayload([]byte("a message"), geo.MaxPlaintextPayloadLength+4)
	require.NoError(t, err)
	box, ct, sigraw, err := idx.EncryptForContext(wc, constants.PIGEONHOLE_CTX, padded)
	require.NoError(t, err)
	var sig [bacap.SignatureSize]byte
	copy(sig[:], sigraw)
	write := &pigeonhole.ReplicaWrite{BoxID: box, Signature: sig, PayloadLen: uint32(len(ct)), Payload: ct}
	paddedWrite, err := pigeonhole.PadInnerMessageForEncryption(
		&pigeonhole.ReplicaInnerMessage{MessageType: 1, WriteMsg: write}, geo)
	require.NoError(t, err)

	require.Equal(t, len(paddedWrite), len(paddedTomb))
}
