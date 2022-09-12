// kem.go - Wire protocol session KEM interfaces.
// Copyright (C) 2022  David Anthony Stainton
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

// Package wire implements the Katzenpost wire protocol.
package wire

import (
	"bytes"
	"crypto/rand"
	"encoding"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/katzenpost/katzenpost/core/utils"
	"github.com/katzenpost/nyquist/kem"
	"github.com/katzenpost/nyquist/seec"
)

// PublicKey is an interface used to abstract away the
// details of the KEM Public Key being used in the wire package.
type PublicKey interface {
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
	encoding.TextMarshaler
	encoding.TextUnmarshaler

	// ToPEMFile writes out the PublicKey to a PEM file at path f.
	ToPEMFile(f string) error

	// FromPEMFile reads the PublicKey from the PEM file at path f.
	FromPEMFile(f string) error

	// Reset clears the PublicKey structure such that no sensitive data is left
	// in memory.
	Reset()

	// Equal returns true if the two public keys are equal.
	Equal(PublicKey) bool

	// Bytes returns the raw public key.
	Bytes() []byte

	// FromBytes deserializes the byte slice b into the PublicKey.
	FromBytes(b []byte) error
}

// PrivateKey is an interface used to abstract away the
// details of the KEM Private Key being used in the wire package.
type PrivateKey interface {

	// Reset clears the PrivateKey structure such that no sensitive data is left
	// in memory.
	Reset()

	// Bytes returns the raw public key.
	Bytes() []byte

	// FromBytes deserializes the byte slice b into the PrivateKey.
	FromBytes(b []byte) error

	// PublicKey returns the PublicKey corresponding to the PrivateKey.
	PublicKey() PublicKey
}

// Scheme provides a minimal abstraction around our KEM Scheme.
type Scheme interface {

	// NewPublicKey returns a new public key.
	NewPublicKey() PublicKey

	// GenerateKeypair generates a new KEM keypair using the provided
	// entropy source.
	GenerateKeypair(r io.Reader) (PrivateKey, error)

	// Load loads a new PrivateKey from the PEM encoded file privFile, optionally
	// creating and saving a PrivateKey instead if an entropy source is provided.
	// If pubFile is specified and a key has been created, the corresponding
	// PublicKey will be wrtten to pubFile in PEM format.
	Load(privFile, pubFile string, r io.Reader) (PrivateKey, error)
}

type publicKey struct {
	publicKey kem.PublicKey
	KEM       kem.KEM
}

func (p *publicKey) FromPEMFile(f string) error {
	keyType := fmt.Sprintf("%s PUBLIC KEY", p.KEM)

	buf, err := ioutil.ReadFile(f)
	if err != nil {
		return err
	}
	blk, _ := pem.Decode(buf)
	if blk == nil {
		return fmt.Errorf("failed to decode PEM file %v", f)
	}
	if blk.Type != keyType {
		return fmt.Errorf("attempted to decode PEM file with wrong key type %v != %v", blk.Type, keyType)
	}
	return p.FromBytes(blk.Bytes)
}

func (p *publicKey) ToPEMFile(f string) error {
	keyType := fmt.Sprintf("%s PUBLIC KEY", p.KEM)

	if utils.CtIsZero(p.Bytes()) {
		return fmt.Errorf("attempted to serialize scrubbed key")
	}
	blk := &pem.Block{
		Type:  keyType,
		Bytes: p.Bytes(),
	}
	return ioutil.WriteFile(f, pem.EncodeToMemory(blk), 0600)
}

// XXX FIXME
func (p *publicKey) Reset() {
	p = nil
}

func (p *publicKey) Equal(publicKey PublicKey) bool {
	return bytes.Equal(publicKey.Bytes(), p.Bytes())
}

func (p *publicKey) FromBytes(b []byte) error {
	publicKey, err := p.KEM.ParsePublicKey(b)
	if err != nil {
		return err
	}
	p.publicKey = publicKey
	return nil
}

func (p *publicKey) Bytes() []byte {
	return p.publicKey.Bytes()
}

func (p *publicKey) MarshalBinary() (data []byte, err error) {
	return p.Bytes(), nil
}

func (p *publicKey) UnmarshalBinary(data []byte) error {
	return p.FromBytes(data)
}

func (p *publicKey) MarshalText() (text []byte, err error) {
	return []byte(base64.StdEncoding.EncodeToString(p.Bytes())), nil
}

func (p *publicKey) UnmarshalText(text []byte) error {
	raw, err := base64.StdEncoding.DecodeString(string(text))
	if err != nil {
		return err
	}
	return p.FromBytes(raw)
}

type privateKey struct {
	privateKey kem.Keypair
	KEM        kem.KEM
}

// XXX FIXME
func (p *privateKey) Reset() {
	p = nil
}

func (p *privateKey) PublicKey() PublicKey {
	return &publicKey{
		publicKey: p.privateKey.Public(),
		KEM:       p.KEM,
	}
}

func (p *privateKey) FromBytes(b []byte) error {
	privateKey, err := p.KEM.ParsePrivateKey(b)
	if err != nil {
		return err
	}
	p.privateKey = privateKey
	return nil
}

func (p *privateKey) Bytes() []byte {
	key, err := p.privateKey.MarshalBinary()
	if err != nil {
		panic(err)
	}
	return key
}

type scheme struct {
	KEM kem.KEM
}

var _ Scheme = (*scheme)(nil)

// NewScheme returns an unexported type that implements the above
// Scheme interface for minimally encapsulating KEM related types
// for non-cryptographic operations such as serialization and so on.
func NewScheme() *scheme {
	return &scheme{
		KEM: kem.Kyber768X25519,
	}
}

func (s *scheme) NewPublicKey() PublicKey {
	privKey, err := s.GenerateKeypair(rand.Reader)
	if err != nil {
		panic(err)
	}
	return privKey.PublicKey()
}

func (s *scheme) GenerateKeypair(r io.Reader) (PrivateKey, error) {
	seecGenRand, err := seec.GenKeyPRPAES(r, 256)
	if err != nil {
		return nil, err
	}
	k, err := s.KEM.GenerateKeypair(seecGenRand)
	if err != nil {
		return nil, err
	}

	return &privateKey{
		KEM:        s.KEM,
		privateKey: k,
	}, nil
}

func (s *scheme) Load(privFile, pubFile string, r io.Reader) (PrivateKey, error) {
	keyType := fmt.Sprintf("%s PRIVATE KEY", s.KEM)

	if buf, err := ioutil.ReadFile(privFile); err == nil {
		defer utils.ExplicitBzero(buf)
		blk, rest := pem.Decode(buf)
		defer utils.ExplicitBzero(blk.Bytes)
		if len(rest) != 0 {
			return nil, fmt.Errorf("trailing garbage after PEM encoded private key")
		}
		if blk.Type != keyType {
			return nil, fmt.Errorf("invalid PEM Type: '%v'", blk.Type)
		}
		k, err := s.KEM.ParsePrivateKey(blk.Bytes)
		if err != nil {
			return nil, err
		}
		return &privateKey{
			KEM:        s.KEM,
			privateKey: k,
		}, nil
	} else if !os.IsNotExist(err) || r == nil {
		return nil, err
	}

	seecGenRand, err := seec.GenKeyPRPAES(r, 256)
	if err != nil {
		return nil, err
	}
	k, err := s.KEM.GenerateKeypair(seecGenRand)
	if err != nil {
		return nil, err
	}

	privKey := &privateKey{
		KEM:        s.KEM,
		privateKey: k,
	}

	blk := &pem.Block{
		Type:  keyType,
		Bytes: privKey.Bytes(),
	}
	if err = ioutil.WriteFile(privFile, pem.EncodeToMemory(blk), 0600); err != nil {
		return nil, err
	}
	if pubFile != "" {
		err = privKey.PublicKey().ToPEMFile(pubFile)
	}
	return privKey, nil
}
