// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package pigeonhole

import (
	"github.com/katzenpost/hpqc/bacap"

	"github.com/katzenpost/katzenpost/client/constants"
)

// BACAP boxes for pigeonhole. These take positions, a capability bound to
// one box on its stream (bacap.WritePosition, bacap.ReadPosition), so a cap
// can never be paired with another stream's index, and apply the pigeonhole
// context (constants.PIGEONHOLE_CTX). Get a position from a cap's Start, or
// from PositionAt for an index that came from elsewhere.

// BoxID returns the ID of the box at p.
func BoxID(p *bacap.ReadPosition) ([bacap.BoxIDSize]byte, error) {
	var box [bacap.BoxIDSize]byte
	pub, err := p.BoxID(constants.PIGEONHOLE_CTX)
	if err != nil {
		return box, err
	}
	copy(box[:], pub.Bytes())
	return box, nil
}

// Seal encrypts and signs payload for the box at w, returning the write
// that stores it.
func Seal(w *bacap.WritePosition, payload []byte) (*ReplicaWrite, error) {
	boxID, ciphertext, sigraw, err := w.Encrypt(constants.PIGEONHOLE_CTX, payload)
	if err != nil {
		return nil, err
	}
	write := &ReplicaWrite{BoxID: boxID, PayloadLen: uint32(len(ciphertext)), Payload: ciphertext}
	copy(write.Signature[:], sigraw)
	return write, nil
}

// NewTombstone returns the write that deletes the box at w: the empty
// payload, signed under that box's key, with no payload. A replica stores
// exactly this as a tombstone; a write that carries any payload, even an
// encrypted empty message, is an ordinary write, which a box already
// holding data refuses.
//
// A tombstone is no shorter on the wire than any other write: the inner
// message is padded to a fixed size before it is encrypted to the replicas
// (see PadInnerMessageForEncryption).
func NewTombstone(w *bacap.WritePosition) (*ReplicaWrite, error) {
	boxID, sigraw, err := w.Tombstone(constants.PIGEONHOLE_CTX)
	if err != nil {
		return nil, err
	}
	write := &ReplicaWrite{BoxID: boxID}
	copy(write.Signature[:], sigraw)
	return write, nil
}

// Open verifies and decrypts a box read back for r. It first checks the box
// is the one r addresses, returning bacap.ErrEmptyBox for an all-zero box
// and bacap.ErrBoxMismatch for any other box. That check is what rejects a
// tombstone signed for another box, which has no ciphertext to authenticate.
func Open(r *bacap.ReadPosition, box [bacap.BoxIDSize]byte, ciphertext []byte, sig []byte) ([]byte, error) {
	return r.Open(constants.PIGEONHOLE_CTX, box, ciphertext, sig)
}
