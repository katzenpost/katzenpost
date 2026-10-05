// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package pigeonhole

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/hpqc/sign/ed25519"

	"github.com/katzenpost/katzenpost/client/constants"
	pgeo "github.com/katzenpost/katzenpost/pigeonhole/geo"
)

func TestSealOpen(t *testing.T) {
	wc, err := bacap.NewWriteCap(rand.Reader)
	require.NoError(t, err)
	here := wc.Start()
	there, err := here.Next()
	require.NoError(t, err)

	w, err := Seal(here, []byte("hello"))
	require.NoError(t, err)
	box, err := BoxID(here.ReadPosition())
	require.NoError(t, err)
	require.Equal(t, box, w.BoxID)
	require.Equal(t, uint32(len(w.Payload)), w.PayloadLen)
	pt, err := Open(here.ReadPosition(), w.BoxID, w.Payload, w.Signature[:])
	require.NoError(t, err)
	require.Equal(t, []byte("hello"), pt)

	// A tombstone for the next box verifies under its own box ID and has
	// nothing to decrypt: DecryptForContext alone accepts it here.
	tomb, err := NewTombstone(there)
	require.NoError(t, err)
	_, err = here.Index().DecryptForContext(tomb.BoxID, constants.PIGEONHOLE_CTX, nil, tomb.Signature[:])
	require.NoError(t, err)
	_, err = Open(here.ReadPosition(), tomb.BoxID, nil, tomb.Signature[:])
	require.ErrorIs(t, err, bacap.ErrBoxMismatch)

	pt, err = Open(there.ReadPosition(), tomb.BoxID, nil, tomb.Signature[:])
	require.NoError(t, err)
	require.Empty(t, pt)

	var zero [bacap.BoxIDSize]byte
	_, err = Open(here.ReadPosition(), zero, w.Payload, w.Signature[:])
	require.ErrorIs(t, err, bacap.ErrEmptyBox)

	tampered := append([]byte{}, w.Payload...)
	tampered[0] ^= 1
	_, err = Open(here.ReadPosition(), w.BoxID, tampered, w.Signature[:])
	require.Error(t, err)
}

// A replica stores a write as a tombstone only when it carries no payload
// and its signature verifies over the empty payload under its box ID
// (replica/handlers.go).
func TestNewTombstone(t *testing.T) {
	wc, err := bacap.NewWriteCap(rand.Reader)
	require.NoError(t, err)
	pos := wc.Start()

	tomb, err := NewTombstone(pos)
	require.NoError(t, err)

	box, err := BoxID(pos.ReadPosition())
	require.NoError(t, err)
	require.Equal(t, box, tomb.BoxID)
	require.Zero(t, tomb.PayloadLen)
	require.Empty(t, tomb.Payload)

	s := ed25519.Scheme()
	key, err := s.UnmarshalBinaryPublicKey(tomb.BoxID[:])
	require.NoError(t, err)
	require.True(t, s.Verify(key, []byte{}, tomb.Signature[:], nil), "signed over the empty payload")
}

// A tombstone travels as long as any other write.
func TestNewTombstonePadsLikeAWrite(t *testing.T) {
	g := pgeo.NewGeometry(1530, schemes.ByName("x25519"))
	wc, err := bacap.NewWriteCap(rand.Reader)
	require.NoError(t, err)
	pos := wc.Start()

	tomb, err := NewTombstone(pos)
	require.NoError(t, err)
	paddedTomb, err := PadInnerMessageForEncryption(&ReplicaInnerMessage{MessageType: 1, WriteMsg: tomb}, g)
	require.NoError(t, err)

	padded, err := CreatePaddedPayload([]byte("a message"), g.MaxPlaintextPayloadLength+4)
	require.NoError(t, err)
	write, err := Seal(pos, padded)
	require.NoError(t, err)
	paddedWrite, err := PadInnerMessageForEncryption(&ReplicaInnerMessage{MessageType: 1, WriteMsg: write}, g)
	require.NoError(t, err)

	require.Equal(t, len(paddedWrite), len(paddedTomb))
}
