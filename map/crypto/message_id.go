// SPDX-FileCopyrightText: Copyright (C) 2021  Masala
// SPDX-License-Identifier: AGPL-3.0-only

// Package crypto provides the core cryptographic protocol primitives.
package crypto

import "github.com/katzenpost/katzenpost/core/crypto/eddsa"

var (
	ReadCap  = []byte("read")
	WriteCap = []byte("write")
)

// MessageID represents a storage address with Read/Write capability
type MessageID [eddsa.PublicKeySize]byte

// ReadPk returns the verifier of ReadCap for this ID
func (m MessageID) ReadVerifier() *eddsa.PublicKey {
	p := new(eddsa.PublicKey)
	if err := p.FromBytes(m[:]); err != nil {
		panic(err)
	}
	return p.Blind(ReadCap)
}

// WritePk returns the verifier of WriteCap for this ID
func (m MessageID) WriteVerifier() *eddsa.PublicKey {
	p := new(eddsa.PublicKey)
	if err := p.FromBytes(m[:]); err != nil {
		panic(err)
	}
	return p.Blind(WriteCap)
}

func (m MessageID) Bytes() []byte {
	return m[:]
}
