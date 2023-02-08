package common

import (
	"github.com/katzenpost/katzenpost/core/crypto/eddsa"
)

var (
	ReadCap  = []byte("read")
	WriteCap = []byte("write")
)

type MessageID [eddsa.PublicKeySize]byte

// ReadPk returns the verifier of ReadCap for this ID
func (m MessageID) ReadPk() *eddsa.PublicKey {
	p := new(eddsa.PublicKey)
	if err := p.FromBytes(m[:]); err != nil {
		// only implemented for eddsa PublicKeys
		panic(err)
	}
	return p.Blind(ReadCap)
}

// WritePk returns the verifier of WriteCap for this ID
func (m MessageID) WritePk() *eddsa.PublicKey {
	p := new(eddsa.PublicKey)
	if err := p.FromBytes(m[:]); err != nil {
		panic(err)
	}
	return p.Blind(WriteCap)
}

func (m MessageID) Bytes() []byte {
	return m[:]
}

// ReadWriteCap describes a Capability that has Read and Write
// capabilities and can return ReadOnly and WriteOnly capabilities
type ReadWriteCap interface {
	Addr(addr []byte) MessageID
	Read(addr []byte) *eddsa.BlindedPrivateKey
	Write(addr []byte) *eddsa.BlindedPrivateKey
	ReadOnly() ReadOnlyCap
	WriteOnly() WriteOnlyCap
}

type ReadOnlyCap interface {
	Addr(addr []byte) MessageID
	Read(addr []byte) *eddsa.BlindedPrivateKey
}

type WriteOnlyCap interface {
	Addr(addr []byte) MessageID
	Write(addr []byte) *eddsa.BlindedPrivateKey
}

// rwCap holds the keys implementing Read/Write Capabilities using blinded ed25519 keys
type rwCap struct {
	// capability root private key from which other keys are derived
	capSk *eddsa.PrivateKey
	capPk *eddsa.PublicKey

	// Read capability keys
	capRSk *eddsa.BlindedPrivateKey
	capRPk *eddsa.PublicKey

	// Write capability keys
	capWSk *eddsa.BlindedPrivateKey
	capWPk *eddsa.PublicKey
}

// roCap holds the keys implementing Read Capabilities using blinded ed25519 keys
type roCap struct {
	// capability root public key to derive address mappings
	capPk *eddsa.PublicKey
	// Read capability keys
	capRSk *eddsa.BlindedPrivateKey
	capRPk *eddsa.PublicKey
}

// woCap holds the keys implementing Write Capabilities using blinded ed25519 keys
type woCap struct {
	// capability root public key to derive address mappings
	capPk *eddsa.PublicKey
	// Write capability keys
	capWSk *eddsa.BlindedPrivateKey
	capWPk *eddsa.PublicKey
}

// Addr returns the capability id (publickey) for addr, used as map address
func (s *rwCap) Addr(addr []byte) MessageID {
	// returns the capability derived from the root key
	// mapping address to a public identity key contained in MessageID
	// which provides ReadPk and WritePk methods to verify Signatures
	// from the Read() and Write() capability keys help by Cap
	capAddr := s.capPk.Blind(addr)
	var id MessageID
	copy(id[:], capAddr.Bytes())
	return id
}

// Addr maps address to a capability ID
func (s *roCap) Addr(addr []byte) MessageID {
	capAddr := s.capPk.Blind(addr)
	var id MessageID
	copy(id[:], capAddr.Bytes())
	return id
}

// Read(addr) returns a key from which to sign the command reading from addr
func (s *roCap) Read(addr []byte) *eddsa.BlindedPrivateKey {
	return s.capRSk.Blind(addr)
}

// Addr maps address to a capability ID
func (s *woCap) Addr(addr []byte) MessageID {
	capAddr := s.capPk.Blind(addr)
	var id MessageID
	copy(id[:], capAddr.Bytes())
	return id
}

// Write(addr) returns a key from which to sign the command writing to addr
func (s *woCap) Write(addr []byte) *eddsa.BlindedPrivateKey {
	return s.capWSk.Blind(addr)
}

// Read(addr) returns a key from which to sign the command reading from addr
func (s *rwCap) Read(addr []byte) *eddsa.BlindedPrivateKey {
	return s.capRSk.Blind(addr)
}

// Write(addr) returns a key from which to sign the command writing to addr
func (s *rwCap) Write(addr []byte) *eddsa.BlindedPrivateKey {
	return s.capWSk.Blind(addr)
}

// RO returns a ReadOnlyCap from RWCap
func (s *rwCap) ReadOnly() ReadOnlyCap {
	return &roCap{capPk: s.capPk, capRSk: s.capRSk, capRPk: s.capRPk}
}

// WO returns a WriteOnlyCap from RWCap
func (s *rwCap) WriteOnly() WriteOnlyCap {
	return &woCap{capPk: s.capPk, capWSk: s.capWSk, capWPk: s.capWPk}
}

// NewCap returns a Cap initialized with capability keys from a root key
func NewRWCap(root *eddsa.PrivateKey) ReadWriteCap {
	pRoot := root.PublicKey()
	c := &rwCap{capSk: root, capPk: pRoot,
		capRSk: root.Blind(ReadCap), capRPk: pRoot.Blind(ReadCap),
		capWSk: root.Blind(WriteCap), capWPk: pRoot.Blind(WriteCap),
	}
	return c
}
