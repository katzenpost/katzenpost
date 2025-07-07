// Copyright (C) 2019, 2021 Yawning Angel. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
// 1. Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright
// notice, this list of conditions and the following disclaimer in the
// documentation and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
// TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
// PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
// TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// Package dh implments the Noise Protocol Framework Diffie-Hellman function
// abstract interface and standard DH functions.
package dh // import "gitlab.com/yawning/nyquist.git/dh"

import (
	"encoding"
	"errors"
	"fmt"
	"io"

	"github.com/oasisprotocol/curve25519-voi/primitives/x25519"
	"gitlab.com/yawning/x448.git"
)

var (
	// ErrMalformedPrivateKey is the error returned when a serialized
	// private key is malformed.
	ErrMalformedPrivateKey = errors.New("nyquist/dh: malformed private key")

	// ErrMalformedPublicKey is the error returned when a serialized public
	// key is malformed.
	ErrMalformedPublicKey = errors.New("nyquist/dh: malformed public key")

	// ErrMismatchedPublicKey is the error returned when a public key for an
	// unexpected algorithm is provided to a DH calculation.
	ErrMismatchedPublicKey = errors.New("nyquist/dh: mismatched public key")

	supportedDHs = map[string]DH{
		"25519": X25519,
		"448":   X448,
	}
)

// DH is a Diffie-Hellman key exchange algorithm.
type DH interface {
	fmt.Stringer

	// GenerateKeypair generates a new Diffie-Hellman keypair using the
	// provided entropy source.
	GenerateKeypair(rng io.Reader) (Keypair, error)

	// ParsePrivateKey parses a binary encoded private key.
	ParsePrivateKey(data []byte) (Keypair, error)

	// ParsePublicKey parses a binary encoded public key.
	ParsePublicKey(data []byte) (PublicKey, error)

	// Size returns the size of public keys and DH outputs in bytes (`DHLEN`).
	Size() int
}

// FromString returns a DH by algorithm name, or nil.
func FromString(s string) DH {
	return supportedDHs[s]
}

// Keypair is a Diffie-Hellman keypair.
type Keypair interface {
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler

	// DropPrivate discards the private key.
	DropPrivate()

	// Public returns the public key of the keypair.
	Public() PublicKey

	// DH performs a Diffie-Hellman calculation between the private key
	// in the keypair and the provided public key.
	DH(publicKey PublicKey) ([]byte, error)
}

// PublicKey is a Diffie-Hellman public key.
type PublicKey interface {
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler

	// Bytes returns the binary serialized public key.
	//
	// Warning: Altering the returned slice is unsupported and will lead
	// to unexpected behavior.
	Bytes() []byte
}

// X25519 is the 25519 DH function.
var X25519 DH = &dh25519{}

type dh25519 struct{}

func (dh *dh25519) String() string {
	return "25519"
}

func (dh *dh25519) GenerateKeypair(rng io.Reader) (Keypair, error) {
	var kp Keypair25519
	if _, err := io.ReadFull(rng, kp.rawPrivateKey[:]); err != nil {
		return nil, err
	}

	x25519.ScalarBaseMult(&kp.publicKey.rawPublicKey, &kp.rawPrivateKey)

	return &kp, nil
}

func (dh *dh25519) ParsePrivateKey(data []byte) (Keypair, error) {
	var kp Keypair25519
	if err := kp.UnmarshalBinary(data); err != nil {
		return nil, err
	}

	return &kp, nil
}

func (dh *dh25519) ParsePublicKey(data []byte) (PublicKey, error) {
	var pk PublicKey25519
	if err := pk.UnmarshalBinary(data); err != nil {
		return nil, err
	}

	return &pk, nil
}

func (dh *dh25519) Size() int {
	return 32
}

// Keypair25519 is a X25519 keypair.
type Keypair25519 struct {
	rawPrivateKey [32]byte
	publicKey     PublicKey25519
}

// MarshalBinary marshals the keypair's private key to binary form.
func (kp *Keypair25519) MarshalBinary() ([]byte, error) {
	out := make([]byte, 0, len(kp.rawPrivateKey))
	return append(out, kp.rawPrivateKey[:]...), nil
}

// UnmarshalBinary unmarshals the keypair's private key from binary form,
// and re-derives the corresponding public key.
func (kp *Keypair25519) UnmarshalBinary(data []byte) error {
	if len(data) != 32 {
		return ErrMalformedPrivateKey
	}

	copy(kp.rawPrivateKey[:], data)
	x25519.ScalarBaseMult(&kp.publicKey.rawPublicKey, &kp.rawPrivateKey)

	return nil
}

// Public returns the public key of the keypair.
func (kp *Keypair25519) Public() PublicKey {
	return &kp.publicKey
}

// DH performs a Diffie-Hellman calculation between the private key in the
// keypair and the provided public key.
func (kp *Keypair25519) DH(publicKey PublicKey) ([]byte, error) {
	pubKey, ok := publicKey.(*PublicKey25519)
	if !ok {
		return nil, ErrMismatchedPublicKey
	}

	// Note: This intentionally used the deprecated API, as per-the
	// Noise specification (r34) 12.1:
	//
	// > Invalid public key values will produce an output of all zeros.
	// >
	// > Alternatively, implementations are allowed to detect inputs that produce an all-zeros
	// > output and signal an error instead. This behavior is discouraged because it adds
	// > complexity and implementation variance, and does not improve security. This behavior is
	// > allowed because it might match the behavior of some software.
	var sharedSecret [32]byte
	x25519.ScalarMult(&sharedSecret, &kp.rawPrivateKey, &pubKey.rawPublicKey) //nolint:staticcheck

	return sharedSecret[:], nil
}

// DropPrivate discards the private key.
func (kp *Keypair25519) DropPrivate() {
	for i := range kp.rawPrivateKey {
		kp.rawPrivateKey[i] = 0
	}
}

// PublicKey25519 is a X25519 public key.
type PublicKey25519 struct {
	rawPublicKey [32]byte
}

// MarshalBinary marshals the public key to binary form.
func (pk *PublicKey25519) MarshalBinary() ([]byte, error) {
	out := make([]byte, 0, len(pk.rawPublicKey))
	return append(out, pk.rawPublicKey[:]...), nil
}

// UnmarshalBinary unmarshals the public key from binary form.
func (pk *PublicKey25519) UnmarshalBinary(data []byte) error {
	if len(data) != 32 {
		return ErrMalformedPublicKey
	}

	copy(pk.rawPublicKey[:], data)

	return nil
}

// Bytes returns the binary serialized public key.
//
// Warning: Altering the returned slice is unsupported and will lead to
// unexpected behavior.
func (pk *PublicKey25519) Bytes() []byte {
	return pk.rawPublicKey[:]
}

// X448 is the X448 DH function.
var X448 DH = &dh448{}

type dh448 struct{}

func (dh *dh448) String() string {
	return "448"
}

func (dh *dh448) GenerateKeypair(rng io.Reader) (Keypair, error) {
	var kp Keypair448
	if _, err := io.ReadFull(rng, kp.rawPrivateKey[:]); err != nil {
		return nil, err
	}

	x448.ScalarBaseMult(&kp.publicKey.rawPublicKey, &kp.rawPrivateKey)

	return &kp, nil
}

func (dh *dh448) ParsePrivateKey(data []byte) (Keypair, error) {
	var kp Keypair448
	if err := kp.UnmarshalBinary(data); err != nil {
		return nil, err
	}

	return &kp, nil
}

func (dh *dh448) ParsePublicKey(data []byte) (PublicKey, error) {
	var pk PublicKey448
	if err := pk.UnmarshalBinary(data); err != nil {
		return nil, err
	}

	return &pk, nil
}

func (dh *dh448) Size() int {
	return 56
}

// Keypair448 is a X448 keypair.
type Keypair448 struct {
	rawPrivateKey [56]byte
	publicKey     PublicKey448
}

// MarshalBinary marshals the keypair's private key to binary form.
func (kp *Keypair448) MarshalBinary() ([]byte, error) {
	out := make([]byte, 0, len(kp.rawPrivateKey))
	return append(out, kp.rawPrivateKey[:]...), nil
}

// UnmarshalBinary unmarshals the keypair's private key from binary form,
// and re-derives the corresponding public key.
func (kp *Keypair448) UnmarshalBinary(data []byte) error {
	if len(data) != 56 {
		return ErrMalformedPrivateKey
	}

	copy(kp.rawPrivateKey[:], data)
	x448.ScalarBaseMult(&kp.publicKey.rawPublicKey, &kp.rawPrivateKey)

	return nil
}

// Public returns the public key of the keypair.
func (kp *Keypair448) Public() PublicKey {
	return &kp.publicKey
}

// DH performs a Diffie-Hellman calculation between the private key in the
// keypair and the provided public key.
func (kp *Keypair448) DH(publicKey PublicKey) ([]byte, error) {
	pubKey, ok := publicKey.(*PublicKey448)
	if !ok {
		return nil, ErrMismatchedPublicKey
	}

	var sharedSecret [56]byte
	x448.ScalarMult(&sharedSecret, &kp.rawPrivateKey, &pubKey.rawPublicKey)

	return sharedSecret[:], nil
}

// DropPrivate discards the private key.
func (kp *Keypair448) DropPrivate() {
	for i := range kp.rawPrivateKey {
		kp.rawPrivateKey[i] = 0
	}
}

// PublicKey448 is a X448 public key.
type PublicKey448 struct {
	rawPublicKey [56]byte
}

// MarshalBinary marshals the public key to binary form.
func (pk *PublicKey448) MarshalBinary() ([]byte, error) {
	out := make([]byte, 0, len(pk.rawPublicKey))
	return append(out, pk.rawPublicKey[:]...), nil
}

// UnmarshalBinary unmarshals the public key from binary form.
func (pk *PublicKey448) UnmarshalBinary(data []byte) error {
	if len(data) != 56 {
		return ErrMalformedPublicKey
	}

	copy(pk.rawPublicKey[:], data)

	return nil
}

// Bytes returns the binary serialized public key.
//
// Warning: Altering the returned slice is unsupported and will lead to
// unexpected behavior.
func (pk *PublicKey448) Bytes() []byte {
	return pk.rawPublicKey[:]
}

// Register registers a new Diffie-Hellman algorithm for use with `FromString()`.
func Register(dh DH) {
	supportedDHs[dh.String()] = dh
}
