// client.go - Reunion Cryptographic client.
// Copyright (C) 2019  David Stainton.
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

package crypto

import (
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"

	"github.com/fxamacker/cbor/v2"

	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/katzenpost/core/utils"
)

const (
	type1Message = "type-1"
	type2Message = "type-2"
	type3Message = "type-3"

	// SharedEpochKeySize is the length of the shared epoch key.
	SharedEpochKeySize = 32
)

type serializableSession struct {
	Epoch             uint64
	SharedRandomValue []byte
	Keypair1          *Keypair
	Keypair2          *Keypair
	SessionKey1       []byte
	SessionKey2       []byte
	SharedEpochKey    []byte
}

// Session encapsulates all the key material
// and provides a few methods for performing
// core cryptographic operations that form the
// Reunion protocol. Note that this so called
// Session does NOT keep any state. Therefore
// these client methods are supplemented with
// some helper functions defined in crypto.go
type Session struct {
	epoch             uint64
	sharedRandomValue []byte
	keypair1          *Keypair
	keypair2          *Keypair
	sessionKey1       *[32]byte
	sessionKey2       *[32]byte
	sharedEpochKey    *[32]byte
}

// NewSessionFromKey creates a new client given a shared epoch key.
func NewSessionFromKey(sharedEpochKey *[SharedEpochKeySize]byte, sharedRandomValue []byte, epoch uint64) (*Session, error) {
	keypair1, err := NewKeypair(true)
	if err != nil {
		return nil, err
	}
	keypair2, err := NewKeypair(false)
	if err != nil {
		return nil, err
	}
	sk1 := &[32]byte{}
	_, err = rand.Reader.Read(sk1[:])
	if err != nil {
		return nil, err
	}
	sk2 := &[32]byte{}
	_, err = rand.Reader.Read(sk2[:])
	if err != nil {
		return nil, err
	}
	client := &Session{
		epoch:             epoch,
		sharedRandomValue: sharedRandomValue,
		keypair1:          keypair1,
		keypair2:          keypair2,
		sessionKey1:       sk1,
		sessionKey2:       sk2,
		sharedEpochKey:    sharedEpochKey,
	}
	return client, nil
}

// NewSession creates a new client given a shared passphrase, shared random value and an epoch number.
func NewSession(passphrase []byte, sharedRandomValue []byte, epoch uint64) (*Session, error) {
	salt := getSalt(sharedRandomValue, epoch)
	// XXX how many iterations should we use?
	// This makes it run for 2.2s on my crappy laptop.
	t := uint32(250)
	memory := uint32(9001)
	threads := uint8(1)
	key := argon2.IDKey(passphrase, salt, t, memory, threads, SharedEpochKeySize)
	k := [SharedEpochKeySize]byte{}
	copy(k[:], key)

	return NewSessionFromKey(&k, sharedRandomValue, epoch)
}

// Epoch returns the epoch.
func (c *Session) Epoch() uint64 {
	return c.epoch
}

// SharedRandom returns the shared random value.
func (c *Session) SharedRandom() []byte {
	return c.sharedRandomValue
}

// Destroy destroys all the Session's key material
// and frees up the memory.
func (c *Session) Destroy() {
	c.keypair1.Destroy()
	c.keypair2.Destroy()
	utils.ExplicitBzero(c.sessionKey1[:])
	utils.ExplicitBzero(c.sessionKey2[:])
	utils.ExplicitBzero(c.sharedEpochKey[:])
}

// GenerateType1Message generates a Type 1 message.
func (c *Session) GenerateType1Message(payload []byte) ([]byte, error) {
	keypair1ElligatorPub := c.keypair1.Representative().Bytes()
	k1, _, err := deriveSprpKey(type1Message, c.sharedRandomValue, c.epoch, c.sharedEpochKey[:])
	if err != nil {
		return nil, err
	}
	iv := [SPRPIVLength]byte{}
	alpha := SPRPEncrypt(k1, &iv, keypair1ElligatorPub[:])

	beta, err := newT1Beta(c.keypair2.Public().Bytes(), c.sessionKey1)
	if err != nil {
		return nil, err
	}

	gamma, err := newT1Gamma(payload[:], c.sessionKey2)
	if err != nil {
		return nil, err
	}

	output := []byte{}
	output = append(output, alpha...)
	output = append(output, beta...)
	output = append(output, gamma...)
	return output, nil
}

// ProcessType1MessageAlpha processes the alpha portion of a type one message.
func (c *Session) ProcessType1MessageAlpha(alpha []byte) ([]byte, *PublicKey, error) {

	k1, _, err := deriveSprpKey(type1Message, c.sharedRandomValue, c.epoch, c.sharedEpochKey[:])
	if err != nil {
		return nil, nil, err
	}

	iv := [SPRPIVLength]byte{}
	elligatorPub1 := SPRPDecrypt(k1, &iv, alpha)

	rKey := [RepresentativeLength]byte{}
	copy(rKey[:], elligatorPub1)
	r := Representative(rKey)
	b1PubKey := r.ToPublic()

	// T2 message construction:
	k2Outer, hkdfContext, err := deriveSprpKey(type2Message, c.sharedRandomValue, c.epoch, c.sharedEpochKey[:])
	if err != nil {
		return nil, nil, err
	}

	k2idh := [32]byte{}
	c.keypair1.Private().Exp(&k2idh, b1PubKey)

	salt := getSalt(c.sharedRandomValue, c.epoch)
	prk2i := hkdf.Extract(HashFunc, k2idh[:], salt)

	kdfReader := hkdf.Expand(HashFunc, prk2i, hkdfContext)
	k2Inner := [SPRPKeyLength]byte{}
	_, err = kdfReader.Read(k2Inner[:])
	if err != nil {
		return nil, nil, err
	}

	k2InnerIV := [SPRPIVLength]byte{}
	k2OuterIV := [SPRPIVLength]byte{}
	t2 := SPRPEncrypt(k2Outer, &k2OuterIV, SPRPEncrypt(&k2Inner, &k2InnerIV, c.sessionKey1[:]))

	return t2, b1PubKey, nil
}

// GetCandidateKey extracts a candidate key from a type two message.
func (c *Session) GetCandidateKey(t2 []byte, alpha *PublicKey) ([]byte, error) {
	k3Outer, hkdfContext, err := deriveSprpKey(type2Message, c.sharedRandomValue, c.epoch, c.sharedEpochKey[:])
	if err != nil {
		return nil, err
	}

	// DH operation
	k3idh := [32]byte{}
	c.keypair1.Private().Exp(&k3idh, alpha)

	// HKDF extract and expand
	salt := getSalt(c.sharedRandomValue, c.epoch)
	prk3i := hkdf.Extract(HashFunc, k3idh[:], salt)

	kdfReader := hkdf.Expand(HashFunc, prk3i, hkdfContext)
	k3Inner := [SPRPKeyLength]byte{}
	_, err = kdfReader.Read(k3Inner[:])
	if err != nil {
		return nil, err
	}

	k3InnerIV := [SPRPIVLength]byte{}
	k3OuterIV := [SPRPIVLength]byte{}

	return SPRPDecrypt(&k3Inner, &k3InnerIV, SPRPDecrypt(k3Outer, &k3OuterIV, t2)), nil
}

// ComposeType3Message composes a type three message.
func (c *Session) ComposeType3Message(beta2 *PublicKey) ([]byte, error) {
	k3Outer, hkdfContext, err := deriveSprpKey(type3Message, c.sharedRandomValue, c.epoch, c.sharedEpochKey[:])
	if err != nil {
		return nil, err
	}

	dh := [32]byte{}
	c.keypair2.Private().Exp(&dh, beta2)

	salt := getSalt(c.sharedRandomValue, c.epoch)
	prk3i := hkdf.Extract(HashFunc, dh[:], salt)
	kdfReader := hkdf.Expand(HashFunc, prk3i, hkdfContext)
	k3Inner := [SPRPKeyLength]byte{}
	_, err = kdfReader.Read(k3Inner[:])
	if err != nil {
		return nil, err
	}

	k3InnerIV := [SPRPIVLength]byte{}
	k3OuterIV := [SPRPIVLength]byte{}
	t3 := SPRPEncrypt(k3Outer, &k3OuterIV, SPRPEncrypt(&k3Inner, &k3InnerIV, c.sessionKey2[:]))
	return t3, nil
}

// ProcessType3Message processes a type three message.
func (c *Session) ProcessType3Message(t3, gamma []byte, beta2 *PublicKey) ([]byte, error) {
	k3Outer, hkdfContext, err := deriveSprpKey(type3Message, c.sharedRandomValue, c.epoch, c.sharedEpochKey[:])
	if err != nil {
		return nil, err
	}

	dh := [32]byte{}
	c.keypair2.Private().Exp(&dh, beta2)

	salt := getSalt(c.sharedRandomValue, c.epoch)
	prk3i := hkdf.Extract(HashFunc, dh[:], salt)
	kdfReader := hkdf.Expand(HashFunc, prk3i, hkdfContext)
	k3Inner := [SPRPKeyLength]byte{}
	_, err = kdfReader.Read(k3Inner[:])
	if err != nil {
		return nil, err
	}

	k3InnerIV := [SPRPIVLength]byte{}
	k3OuterIV := [SPRPIVLength]byte{}
	gammaKey := SPRPDecrypt(&k3Inner, &k3InnerIV, SPRPDecrypt(k3Outer, &k3OuterIV, t3))

	payload, err := decryptT1Gamma(gammaKey, gamma)
	if err != nil {
		return nil, err
	}
	return payload, nil
}

// Marshal serializes the client key material.
func (c *Session) MarshalBinary() ([]byte, error) {
	cc := serializableSession{
		Epoch:             c.epoch,
		SharedRandomValue: c.sharedRandomValue,
		Keypair1:          c.keypair1,
		Keypair2:          c.keypair2,
		SessionKey1:       c.sessionKey1[:],
		SessionKey2:       c.sessionKey2[:],
		SharedEpochKey:    c.sharedEpochKey[:],
	}
	return cbor.Marshal(cc)
}

// Unmarshal deserializes the client key material.
func (c *Session) UnmarshalBinary(data []byte) error {
	cc := new(serializableSession)
	err := cbor.Unmarshal(data, cc)
	if err != nil {
		return err
	}
	c.epoch = cc.Epoch
	c.sharedRandomValue = cc.SharedRandomValue
	c.keypair1 = cc.Keypair1
	c.keypair2 = cc.Keypair2
	c.sessionKey1 = &[32]byte{}
	c.sessionKey2 = &[32]byte{}
	c.sharedEpochKey = &[32]byte{}
	copy(c.sessionKey1[:], cc.SessionKey1)
	copy(c.sessionKey2[:], cc.SessionKey2)
	copy(c.sharedEpochKey[:], cc.SharedEpochKey)
	return nil
}
