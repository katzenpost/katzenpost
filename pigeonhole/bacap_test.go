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

	pgeo "github.com/katzenpost/katzenpost/pigeonhole/geo"
)

func TestOpenBox(t *testing.T) {
	ctx := []byte("pigeonhole context")
	wc, err := bacap.NewWriteCap(rand.Reader)
	require.NoError(t, err)
	rc := wc.ReadCap()
	here := wc.GetMessageBoxIndex()
	there, err := here.NextIndex()
	require.NoError(t, err)

	box, ct, sig, err := here.EncryptForContext(wc, ctx, []byte("hello"))
	require.NoError(t, err)
	pt, err := OpenBox(rc, here, ctx, box, ct, sig)
	require.NoError(t, err)
	require.Equal(t, []byte("hello"), pt)

	// A tombstone for the next box verifies under its own box ID and has
	// nothing to decrypt: DecryptForContext alone accepts it here.
	tbox, tsig, err := there.SignBox(wc, ctx, []byte{})
	require.NoError(t, err)
	_, err = here.DecryptForContext(tbox, ctx, []byte{}, tsig)
	require.NoError(t, err)
	_, err = OpenBox(rc, here, ctx, tbox, []byte{}, tsig)
	require.ErrorIs(t, err, ErrBoxMismatch)

	pt, err = OpenBox(rc, there, ctx, tbox, []byte{}, tsig)
	require.NoError(t, err)
	require.Empty(t, pt)

	var zero [bacap.BoxIDSize]byte
	_, err = OpenBox(rc, here, ctx, zero, ct, sig)
	require.ErrorIs(t, err, ErrEmptyBox)

	tampered := append([]byte{}, ct...)
	tampered[0] ^= 1
	_, err = OpenBox(rc, here, ctx, box, tampered, sig)
	require.Error(t, err)
}

// A replica stores a write as a tombstone only when it carries no payload
// and its signature verifies over the empty payload under its box ID
// (replica/handlers.go).
func TestNewTombstone(t *testing.T) {
	ctx := []byte("pigeonhole context")
	wc, err := bacap.NewWriteCap(rand.Reader)
	require.NoError(t, err)
	idx := wc.GetMessageBoxIndex()

	tomb, err := NewTombstone(wc, idx, ctx)
	require.NoError(t, err)

	box, err := idx.BoxIDForContext(wc.ReadCap(), ctx)
	require.NoError(t, err)
	require.Equal(t, box.Bytes(), tomb.BoxID[:])
	require.Zero(t, tomb.PayloadLen)
	require.Empty(t, tomb.Payload)

	s := ed25519.Scheme()
	key, err := s.UnmarshalBinaryPublicKey(tomb.BoxID[:])
	require.NoError(t, err)
	require.True(t, s.Verify(key, []byte{}, tomb.Signature[:], nil), "signed over the empty payload")

	// Read back, it opens as an empty message at its own box and nowhere else.
	pt, err := OpenBox(wc.ReadCap(), idx, ctx, tomb.BoxID, tomb.Payload, tomb.Signature[:])
	require.NoError(t, err)
	require.Empty(t, pt)
	next, err := idx.NextIndex()
	require.NoError(t, err)
	_, err = OpenBox(wc.ReadCap(), next, ctx, tomb.BoxID, tomb.Payload, tomb.Signature[:])
	require.ErrorIs(t, err, ErrBoxMismatch)
}

// A tombstone travels as long as any other write.
func TestNewTombstonePadsLikeAWrite(t *testing.T) {
	ctx := []byte("pigeonhole context")
	g := pgeo.NewGeometry(1530, schemes.ByName("x25519"))
	wc, err := bacap.NewWriteCap(rand.Reader)
	require.NoError(t, err)
	idx := wc.GetMessageBoxIndex()

	tomb, err := NewTombstone(wc, idx, ctx)
	require.NoError(t, err)
	paddedTomb, err := PadInnerMessageForEncryption(&ReplicaInnerMessage{MessageType: 1, WriteMsg: tomb}, g)
	require.NoError(t, err)

	padded, err := CreatePaddedPayload([]byte("a message"), g.MaxPlaintextPayloadLength+4)
	require.NoError(t, err)
	box, ct, sigraw, err := idx.EncryptForContext(wc, ctx, padded)
	require.NoError(t, err)
	write := &ReplicaWrite{BoxID: box, PayloadLen: uint32(len(ct)), Payload: ct}
	copy(write.Signature[:], sigraw)
	paddedWrite, err := PadInnerMessageForEncryption(&ReplicaInnerMessage{MessageType: 1, WriteMsg: write}, g)
	require.NoError(t, err)

	require.Equal(t, len(paddedWrite), len(paddedTomb))
}
