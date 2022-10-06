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
	"fmt"
	"io"

	"github.com/katzenpost/katzenpost/core/crypto/pem"
	"github.com/katzenpost/nyquist/kem"
	"github.com/katzenpost/nyquist/seec"
)

var DefaultScheme = &scheme{
	KEM: kem.Kyber768X25519,
}

// PublicKey is an interface used to abstract away the
// details of the KEM Public Key being used in the wire package.
type PublicKey interface {
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
	encoding.TextMarshaler
	encoding.TextUnmarshaler

	// KeyType returns the key type string
	KeyType() string

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
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
	encoding.TextMarshaler
	encoding.TextUnmarshaler

	// KeyType returns the key type string
	KeyType() string

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
	// PrivateKeyFromPemFile unmarshals a private key from the PEM file,
	// specified as file path.
	PrivateKeyFromPemFile(f string) (PrivateKey, error)

	// PrivateKeyToPemFile writes the given private key to
	// the specified file path.
	PrivateKeyToPemFile(f string, privKey PrivateKey) error

	// PublicKeyFromPemFile unmarshals a public key from the PEM file,
	// specified as file path.
	PublicKeyFromPemFile(f string) (PublicKey, error)

	// PublicKeyToPemFile writes the given public key to
	// the specified file path.
	PublicKeyToPemFile(f string, pubKey PublicKey) error

	// UnmarshalTextPrivateKey loads a private from text encoded in base64.
	UnmarshalTextPrivateKey([]byte) (PrivateKey, error)

	// UnmarshalTextPublicKey loads a public key from text encoded in base64.
	UnmarshalTextPublicKey([]byte) (PublicKey, error)

	// UnmarshalBinaryPublicKey loads a public key from byte slice.
	UnmarshalBinaryPublicKey([]byte) (PublicKey, error)

	// GenerateKeypair generates a new KEM keypair using the provided
	// entropy source.
	GenerateKeypair(r io.Reader) PrivateKey
}

type publicKey struct {
	publicKey kem.PublicKey
	KEM       kem.KEM
}

func (p *publicKey) KeyType() string {
	return fmt.Sprintf("%s PUBLIC KEY", p.KEM)
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

func (p *privateKey) KeyType() string {
	return fmt.Sprintf("%s PRIVATE KEY", p.KEM)
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

func (p *privateKey) MarshalBinary() (data []byte, err error) {
	return p.Bytes(), nil
}

func (p *privateKey) UnmarshalBinary(data []byte) error {
	return p.FromBytes(data)
}

func (p *privateKey) MarshalText() (text []byte, err error) {
	return []byte(base64.StdEncoding.EncodeToString(p.Bytes())), nil
}

func (p *privateKey) UnmarshalText(text []byte) error {
	raw, err := base64.StdEncoding.DecodeString(string(text))
	if err != nil {
		return err
	}
	return p.FromBytes(raw)
}

type scheme struct {
	KEM kem.KEM
}

var _ Scheme = (*scheme)(nil)

func (s *scheme) PrivateKeyFromPemFile(f string) (PrivateKey, error) {
	privKey := s.GenerateKeypair(rand.Reader)
	err := pem.FromFile(f, privKey)
	if err != nil {
		return nil, err
	}
	return privKey, nil
}

func (s *scheme) PrivateKeyToPemFile(f string, privKey PrivateKey) error {
	return pem.ToFile(f, privKey)
}

func (s *scheme) PublicKeyFromPemFile(f string) (PublicKey, error) {
	pubKey := s.GenerateKeypair(rand.Reader).PublicKey()
	err := pem.FromFile(f, pubKey)
	if err != nil {
		return nil, err
	}
	return pubKey, nil
}

func (s *scheme) PublicKeyToPemFile(f string, pubKey PublicKey) error {
	return pem.ToFile(f, pubKey)
}

func (s *scheme) UnmarshalTextPublicKey(b []byte) (PublicKey, error) {
	privKey := s.GenerateKeypair(rand.Reader)
	pubKey := privKey.PublicKey()
	err := pubKey.UnmarshalText(b)
	if err != nil {
		return nil, err
	}
	return pubKey, nil
}

func (s *scheme) UnmarshalTextPrivateKey(b []byte) (PrivateKey, error) {
	privKey := s.GenerateKeypair(rand.Reader)
	err := privKey.UnmarshalText(b)
	if err != nil {
		return nil, err
	}
	return privKey, nil
}

func (s *scheme) UnmarshalBinaryPublicKey(b []byte) (PublicKey, error) {
	privKey := s.GenerateKeypair(rand.Reader)
	pubKey := privKey.PublicKey()
	err := pubKey.UnmarshalBinary(b)
	if err != nil {
		return nil, err
	}
	return pubKey, nil
}

func (s *scheme) GenerateKeypair(r io.Reader) PrivateKey {
	seecGenRand, err := seec.GenKeyPRPAES(r, 256)
	if err != nil {
		panic(err)
	}
	k, err := s.KEM.GenerateKeypair(seecGenRand)
	if err != nil {
		panic(err)
	}
	return &privateKey{
		KEM:        s.KEM,
		privateKey: k,
	}
}
