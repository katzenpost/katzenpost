// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// Package crypto provides the core cryptographic protocol primitives.
package crypto

import (
	"crypto/sha256"

	"github.com/katzenpost/katzenpost/core/crypto/eddsa"
	"golang.org/x/crypto/hkdf"
)

type RootCapability struct {
	PublicKey *eddsa.PublicKey
}

// ForAddr returns a read capability for the given address.
func (s *RootCapability) ForAddr(addr []byte) MessageID {
	capAddr := s.PublicKey.Blind(addr)
	var id MessageID
	copy(id[:], capAddr.Bytes())
	return id
}

type ReadOnlyCapability struct {
	RootCapability

	PrivateKey *eddsa.BlindedPrivateKey
	PublicKey  *eddsa.PublicKey
}

func NewReadOnlyCapability(root *eddsa.PublicKey, blindedPrivateKey *eddsa.BlindedPrivateKey) *ReadOnlyCapability {
	return &ReadOnlyCapability{
		RootCapability: RootCapability{
			PublicKey: root,
		},
		PrivateKey: blindedPrivateKey,
		PublicKey:  blindedPrivateKey.PublicKey(),
	}
}

// ForAddr returns a read capability for the given address.
func (r *ReadOnlyCapability) ForAddr(addr []byte) *eddsa.BlindedPrivateKey {
	return r.PrivateKey.Blind(addr)
}

func (r *ReadOnlyCapability) ReadCapForAddr(addr []byte) *ReadCapability {
	id := r.RootCapability.ForAddr(addr)
	readAddrCap := r.ForAddr(addr)
	signed := readAddrCap.Sign(id.Bytes())
	return &ReadCapability{
		ID:        &id,
		Signature: signed,
	}
}

type WriteOnlyCapability struct {
	RootCapability

	PrivateKey *eddsa.BlindedPrivateKey
	PublicKey  *eddsa.PublicKey
}

func NewWriteOnlyCapability(root *eddsa.PublicKey, blindedPrivateKey *eddsa.BlindedPrivateKey) *WriteOnlyCapability {
	return &WriteOnlyCapability{
		RootCapability: RootCapability{
			PublicKey: root,
		},
		PrivateKey: blindedPrivateKey,
		PublicKey:  blindedPrivateKey.PublicKey(),
	}
}

// ForAddr returns a write capability for the given address.
func (w *WriteOnlyCapability) ForAddr(addr []byte) *eddsa.BlindedPrivateKey {
	return w.PrivateKey.Blind(addr)
}

func (w *WriteOnlyCapability) WriteCapForAddr(addr, payload []byte) *WriteCapability {
	id := w.RootCapability.ForAddr(addr)
	readAddrCap := w.ForAddr(addr)
	signed := readAddrCap.Sign(payload)
	return &WriteCapability{
		ID:        &id,
		Signature: signed,
		Payload:   payload,
	}
}

type ReadWriteCapability struct {
	RootCapability
	ReadOnlyCapability
	WriteOnlyCapability

	PrivateKey *eddsa.PrivateKey
}

func NewReadWriteCapability(root *eddsa.PrivateKey) *ReadWriteCapability {
	rootPub := root.PublicKey()
	return &ReadWriteCapability{
		PrivateKey: root,
		RootCapability: RootCapability{
			PublicKey: rootPub,
		},
		ReadOnlyCapability: ReadOnlyCapability{
			RootCapability: RootCapability{
				PublicKey: rootPub,
			},
			PrivateKey: root.Blind(ReadCap),
			PublicKey:  rootPub.Blind(ReadCap),
		},
		WriteOnlyCapability: WriteOnlyCapability{
			RootCapability: RootCapability{
				PublicKey: rootPub,
			},
			PrivateKey: root.Blind(WriteCap),
			PublicKey:  rootPub.Blind(WriteCap),
		},
	}
}

func (c *ReadWriteCapability) DiminishToReadOnly() *ReadOnlyCapability {
	return &ReadOnlyCapability{
		RootCapability: RootCapability{
			PublicKey: c.RootCapability.PublicKey,
		},
		PrivateKey: c.ReadOnlyCapability.PrivateKey,
		PublicKey:  c.ReadOnlyCapability.PublicKey,
	}
}

func (c *ReadWriteCapability) DiminishToWriteOnly() *WriteOnlyCapability {
	return &WriteOnlyCapability{
		RootCapability: RootCapability{
			PublicKey: c.RootCapability.PublicKey,
		},
		PrivateKey: c.WriteOnlyCapability.PrivateKey,
		PublicKey:  c.WriteOnlyCapability.PublicKey,
	}
}

func (c *ReadWriteCapability) ReadCapForAddr(addr []byte) *ReadCapability {
	id := c.RootCapability.ForAddr(addr)
	readAddrCap := c.ReadOnlyCapability.ForAddr(addr)
	signed := readAddrCap.Sign(id.Bytes())
	return &ReadCapability{
		ID:        &id,
		Signature: signed,
	}
}

func (c *ReadWriteCapability) WriteCapForAddr(addr, payload []byte) *WriteCapability {
	id := c.RootCapability.ForAddr(addr)
	readAddrCap := c.WriteOnlyCapability.ForAddr(addr)
	signed := readAddrCap.Sign(payload)
	return &WriteCapability{
		ID:        &id,
		Signature: signed,
		Payload:   payload,
	}
}

type ReadCapability struct {
	// ID is the ID of the storage slot
	ID *MessageID

	// Signature is the signature over Payload with
	// the read capability keys for the entry
	// identified by ID
	Signature []byte
}

// Verify returns true if the capability is internally consistent
// in terms of having a valid signature.
func (r *ReadCapability) Verify() bool {
	return r.ID.ReadVerifier().Verify(r.Signature, r.ID.Bytes())
}

type WriteCapability struct {
	// ID is the ID of the storage slot
	ID *MessageID

	// Signature is the signature over Payload with
	// the Write capability keys for the entry
	// identified by ID
	Signature []byte

	// Payload is the contents to store or nil
	Payload []byte
}

// Verify returns true if the capability is internally consistent
// in terms of having a valid signature.
func (r *WriteCapability) Verify() bool {
	return r.ID.WriteVerifier().Verify(r.Signature, r.Payload)
}

type DuplexCapabilty struct {
	ReadOnlyCap  *ReadOnlyCapability
	WriteOnlyCap *WriteOnlyCapability
}

func DuplexFromSeed(initiator bool, seed []byte) *DuplexCapabilty {
	salt := []byte("katzenpost-map-duplex-salt")
	rng := hkdf.New(sha256.New, seed, salt, nil)
	var err error
	var pk1, pk2 *eddsa.PrivateKey
	if initiator {
		pk1, err = eddsa.NewKeypair(rng)
		if err != nil {
			panic(err)
		}
		pk2, err = eddsa.NewKeypair(rng)
		if err != nil {
			panic(err)
		}
	} else {
		pk2, err = eddsa.NewKeypair(rng)
		if err != nil {
			panic(err)
		}
		pk1, err = eddsa.NewKeypair(rng)
		if err != nil {
			panic(err)
		}
	}
	rw1 := NewReadWriteCapability(pk1)
	rw2 := NewReadWriteCapability(pk2)
	return &DuplexCapabilty{
		ReadOnlyCap:  rw1.DiminishToReadOnly(),
		WriteOnlyCap: rw2.DiminishToWriteOnly(),
	}
}
