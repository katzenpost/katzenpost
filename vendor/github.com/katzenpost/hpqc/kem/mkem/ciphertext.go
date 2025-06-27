// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// Package mkem provides multiparty KEM construction.
package mkem

import (
	"github.com/fxamacker/cbor/v2"

	"github.com/katzenpost/hpqc/nike"
)

var (
	// Create reusable EncMode interface with immutable options, safe for concurrent use.
	ccbor cbor.EncMode
)

type Ciphertext struct {
	EphemeralPublicKey nike.PublicKey
	DEKCiphertexts     []*[DEKSize]byte
	Envelope           []byte
}

type IntermediaryCiphertext struct {
	EphemeralPublicKey []byte
	DEKCiphertexts     []*[DEKSize]byte
	Envelope           []byte
}

func (i *IntermediaryCiphertext) Bytes() []byte {
	blob, err := ccbor.Marshal(i)
	if err != nil {
		panic(err)
	}
	return blob
}

func (i *IntermediaryCiphertext) FromBytes(b []byte) error {
	err := cbor.Unmarshal(b, i)
	if err != nil {
		return err
	}
	return nil
}

func CiphertextFromBytes(scheme *Scheme, b []byte) (*Ciphertext, error) {
	ic := &IntermediaryCiphertext{}
	err := ic.FromBytes(b)
	if err != nil {
		return nil, err
	}
	pubkey, err := scheme.nike.UnmarshalBinaryPublicKey(ic.EphemeralPublicKey)
	if err != nil {
		return nil, err
	}
	c := &Ciphertext{
		EphemeralPublicKey: pubkey,
		DEKCiphertexts:     ic.DEKCiphertexts,
		Envelope:           ic.Envelope,
	}
	return c, nil
}

func (m *Ciphertext) Marshal() []byte {
	ic := &IntermediaryCiphertext{
		EphemeralPublicKey: m.EphemeralPublicKey.Bytes(),
		DEKCiphertexts:     m.DEKCiphertexts,
		Envelope:           m.Envelope,
	}
	return ic.Bytes()
}

func init() {
	var err error
	opts := cbor.CanonicalEncOptions()
	ccbor, err = opts.EncMode()
	if err != nil {
		panic(err)
	}
}
