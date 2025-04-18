// Copyright (C) 2021  Masala
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package common

import (
	"bytes"
	"github.com/katzenpost/hpqc/sign/ed25519"
)

var (
	ReadCap  = []byte("read")
	WriteCap = []byte("write")
)

// MessageID represents a storage address with Read/Write capability
type MessageID [ed25519.PublicKeySize]byte

// ReadVerifier returns the verifier of ReadCap for this ID
func (m MessageID) ReadVerifier() *ed25519.PublicKey {
	p := new(ed25519.PublicKey)
	if err := p.FromBytes(m[:]); err != nil {
		panic(err)
	}
	return p.Blind(ReadCap)
}

// WriteVerifier returns the verifier of WriteCap for this ID
func (m MessageID) WriteVerifier() *ed25519.PublicKey {
	p := new(ed25519.PublicKey)
	if err := p.FromBytes(m[:]); err != nil {
		panic(err)
	}
	return p.Blind(WriteCap)
}

func (m MessageID) Bytes() []byte {
	return m[:]
}

type Cap interface {
	Addr(addr []byte) MessageID
}

// ReadWriteCap describes a Capability that has Read and Write
// capabilities and can return ReadOnly and WriteOnly capabilities
type ReadWriteCap interface {
	Cap
	ReadOnlyCap
	WriteOnlyCap
	ReadOnly() ReadOnlyCap
	WriteOnly() WriteOnlyCap
}

// ReadOnlyCap describes a Capability that has Read capability only.
type ReadOnlyCap interface {
	Cap
	ReadKey(addr []byte) *ed25519.BlindedPrivateKey
}

// ReadOnlyCap describes a Capability that has Write capability only.
type WriteOnlyCap interface {
	Cap
	WriteKey(addr []byte) *ed25519.BlindedPrivateKey
}

// RootCap holds CapPk and implements the Addr method which other capability types inherit.
type RootCap struct {
	CapPk *ed25519.PublicKey
}

// Addr returns the capability id (publickey) for addr, used as map address
func (s *RootCap) Addr(addr []byte) MessageID {
	// returns the capability derived from the root key
	// mapping address to a public identity key contained in MessageID
	// which provides ReadVerifier and WriteVerifier methods to verify Signatures
	// from the ReadKey() and WriteKey() capability keys help by Cap
	capAddr := s.CapPk.Blind(addr)
	var id MessageID
	copy(id[:], capAddr.Bytes())
	return id
}

// RWCap holds the keys implementing Read/Write Capabilities using blinded ed25519 keys
type RWCap struct {
	RootCap
	ROCap
	WOCap
	// capability root private key from which other keys are derived
	CapSk *ed25519.PrivateKey
}

// ROCap holds the keys implementing Read Capabilities using blinded ed25519 keys
type ROCap struct {
	RootCap
	// Read capability keys
	CapRSk *ed25519.BlindedPrivateKey
	CapRPk *ed25519.PublicKey
}

// WOCap holds the keys implementing Write Capabilities using blinded ed25519 keys
type WOCap struct {
	RootCap
	// Write capability keys
	CapWSk *ed25519.BlindedPrivateKey
	CapWPk *ed25519.PublicKey
}

// ReadKey(addr) returns a key from which to sign the command reading from addr
func (s *ROCap) ReadKey(addr []byte) *ed25519.BlindedPrivateKey {
	return s.CapRSk.Blind(addr)
}

// WriteKey(addr) returns a key from which to sign the command writing to addr
func (s *WOCap) WriteKey(addr []byte) *ed25519.BlindedPrivateKey {
	return s.CapWSk.Blind(addr)
}

// RO returns a ReadOnlyCap from RWCap
func (s *RWCap) ReadOnly() *ROCap {
	ro := &ROCap{}
	ro.CapPk = s.CapPk
	ro.CapRSk = s.CapRSk
	ro.CapRPk = s.CapRPk
	return ro
}

// WO returns a WriteOnlyCap from RWCap
func (s *RWCap) WriteOnly() *WOCap {
	wo := &WOCap{}
	wo.CapPk = s.CapPk
	wo.CapWSk = s.CapWSk
	wo.CapWPk = s.CapWPk
	return wo
}

// NewROCap returns a Cap initialized with read capability and root public key
func NewWOCap(pRoot *ed25519.PublicKey, wSk *ed25519.BlindedPrivateKey) *WOCap {
	wo := &WOCap{}
	wo.CapPk = pRoot
	wo.CapWSk = wSk
	if !bytes.Equal(wSk.PublicKey().Bytes(), pRoot.Blind(WriteCap).Bytes()) {
		panic("capability root public key is not root for WO capability")
	}
	return wo
}

// NewROCap returns a Cap initialized with read capability and root public key
func NewROCap(pRoot *ed25519.PublicKey, rSk *ed25519.BlindedPrivateKey) *ROCap {
	ro := &ROCap{}
	ro.CapPk = pRoot
	ro.CapRSk = rSk
	if !bytes.Equal(rSk.PublicKey().Bytes(), pRoot.Blind(ReadCap).Bytes()) {
		panic("capability root public key is not root for RO capability")
	}
	return ro
}

// NewRWCap returns a Cap initialized with capability keys from a root key
func NewRWCap(root *ed25519.PrivateKey) *RWCap {
	pRoot := root.PublicKey()
	rw := &RWCap{}
	rw.CapSk = root
	rw.CapPk = pRoot
	rw.CapRSk = root.Blind(ReadCap)
	rw.CapRPk = pRoot.Blind(ReadCap)
	rw.CapWSk = root.Blind(WriteCap)
	rw.CapWPk = pRoot.Blind(WriteCap)
	return rw
}
