// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package pigeonhole

import (
	"crypto/subtle"
	"errors"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/util"
)

var (
	// ErrEmptyBox is returned by OpenBox for an all-zero box ID.
	ErrEmptyBox = errors.New("empty box, no message received")

	// ErrBoxMismatch is returned by OpenBox when the box is not the one the
	// read cap and index derive.
	ErrBoxMismatch = errors.New("reply does not match expected box ID")
)

// OpenBox verifies and decrypts the box at idx on readCap's stream. It is the
// stateless form of bacap.StatefulReader.DecryptNext: it first checks the box
// is the one readCap and idx derive under ctx, then calls DecryptForContext.
//
// The check matters most for tombstones. A tombstone has no ciphertext to
// authenticate, so DecryptForContext alone accepts a tombstone signed for any
// box; only comparing box IDs ties it to this one.
func OpenBox(readCap *bacap.ReadCap, idx *bacap.MessageBoxIndex, ctx []byte,
	box [bacap.BoxIDSize]byte, ciphertext []byte, sig []byte) ([]byte, error) {
	if util.CtIsZero(box[:]) {
		return nil, ErrEmptyBox
	}
	expected, err := idx.BoxIDForContext(readCap, ctx)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(box[:], expected.Bytes()) != 1 {
		return nil, ErrBoxMismatch
	}
	return idx.DecryptForContext(box, ctx, ciphertext, sig)
}

// NewTombstone returns the write that deletes the box at idx on writeCap's
// stream: the empty payload, signed under that box's key, with no payload.
// A replica stores exactly this as a tombstone; a write that carries any
// payload, even an encrypted empty message, is an ordinary write, which a
// box already holding data refuses.
//
// A tombstone is no shorter on the wire than any other write: the inner
// message is padded to a fixed size before it is encrypted to the replicas
// (see PadInnerMessageForEncryption).
func NewTombstone(writeCap *bacap.WriteCap, idx *bacap.MessageBoxIndex, ctx []byte) (*ReplicaWrite, error) {
	boxID, sigraw, err := idx.SignBox(writeCap, ctx, []byte{})
	if err != nil {
		return nil, err
	}
	w := &ReplicaWrite{BoxID: boxID}
	copy(w.Signature[:], sigraw)
	return w, nil
}
