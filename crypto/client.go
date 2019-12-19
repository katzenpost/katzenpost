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
	"github.com/awnumar/memguard"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/ugorji/go/codec"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

var cborHandle = new(codec.CborHandle)

const (
	type1Message = "type-1"
	type2Message = "type-2"
	type3Message = "type-3"

	// SharedEpochKeySize is the length of the shared epoch key.
	SharedEpochKeySize = 32
)

type clientCbor struct {
	Keypair1       *Keypair
	Keypair2       *Keypair
	SessionKey1    []byte
	SessionKey2    []byte
	SharedEpochKey []byte
}

type Client struct {
	keypair1       *Keypair
	keypair2       *Keypair
	sessionKey1    *memguard.LockedBuffer
	sessionKey2    *memguard.LockedBuffer
	sharedEpochKey *memguard.LockedBuffer
}

func NewClientFromKey(sharedEpochKey *[SharedEpochKeySize]byte) (*Client, error) {
	keypair1, err := NewKeypair(true)
	if err != nil {
		return nil, err
	}
	keypair2, err := NewKeypair(false)
	if err != nil {
		return nil, err
	}
	client := &Client{
		keypair1:       keypair1,
		keypair2:       keypair2,
		sessionKey1:    memguard.NewBufferFromReader(rand.Reader, 32),
		sessionKey2:    memguard.NewBufferFromReader(rand.Reader, 32),
		sharedEpochKey: memguard.NewBufferFromBytes(sharedEpochKey[:]),
	}
	return client, nil
}

func NewClient(passphrase []byte, sharedRandomValue []byte, epoch uint64) (*Client, error) {
	salt := getSalt(sharedRandomValue, epoch)
	t := uint32(9001)
	memory := uint32(9001)
	threads := uint8(1)
	key := argon2.IDKey(passphrase, salt, t, memory, threads, SharedEpochKeySize)
	k := [SharedEpochKeySize]byte{}
	copy(k[:], key)
	memguard.WipeBytes(key)
	return NewClientFromKey(&k)
}

func (c *Client) GenerateType1Message(epoch uint64, sharedRandomValue, payload []byte) ([]byte, error) {
	keypair1ElligatorPub := c.keypair1.Representative().Bytes()
	k1, _, err := deriveSprpKey(type1Message, sharedRandomValue, epoch, c.sharedEpochKey.Bytes())
	if err != nil {
		return nil, err
	}
	iv := [SPRPIVLength]byte{}
	alpha := SPRPEncrypt(k1, &iv, keypair1ElligatorPub[:])

	beta, err := newT1Beta(c.keypair2.Public().Bytes(), c.sessionKey1.ByteArray32())
	if err != nil {
		return nil, err
	}

	gamma, err := newT1Gamma(payload[:], c.sessionKey2.ByteArray32())
	if err != nil {
		return nil, err
	}

	output := []byte{}
	output = append(output, alpha...)
	output = append(output, beta...)
	output = append(output, gamma...)
	return output, nil
}

func (c *Client) ProcessType1MessageAlpha(alpha []byte, sharedRandomValue []byte, epoch uint64) ([]byte, *PublicKey, error) {

	k1, _, err := deriveSprpKey(type1Message, sharedRandomValue, epoch, c.sharedEpochKey.Bytes())
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
	k2Outer, hkdfContext, err := deriveSprpKey(type2Message, sharedRandomValue, epoch, c.sharedEpochKey.Bytes())
	if err != nil {
		return nil, nil, err
	}

	k2idh := [32]byte{}
	c.keypair1.Private().Exp(&k2idh, b1PubKey)

	salt := getSalt(sharedRandomValue, epoch)
	prk2i := hkdf.Extract(HashFunc, k2idh[:], salt)

	kdfReader := hkdf.Expand(HashFunc, prk2i, hkdfContext)
	k2Inner := [SPRPKeyLength]byte{}
	_, err = kdfReader.Read(k2Inner[:])
	if err != nil {
		return nil, nil, err
	}

	k2InnerIV := [SPRPIVLength]byte{}
	k2OuterIV := [SPRPIVLength]byte{}
	t2 := SPRPEncrypt(k2Outer, &k2OuterIV, SPRPEncrypt(&k2Inner, &k2InnerIV, c.sessionKey1.Bytes()))

	return t2, b1PubKey, nil
}

func (c *Client) GetCandidateKey(t2 []byte, alpha *PublicKey, epoch uint64, sharedRandomValue []byte) ([]byte, error) {
	k3Outer, hkdfContext, err := deriveSprpKey(type2Message, sharedRandomValue, epoch, c.sharedEpochKey.Bytes())
	if err != nil {
		return nil, err
	}

	// DH operation
	k3idh := [32]byte{}
	c.keypair1.Private().Exp(&k3idh, alpha)

	// HKDF extract and expand
	salt := getSalt(sharedRandomValue, epoch)
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

func (c *Client) ComposeType3Message(beta2 *PublicKey, sharedRandomValue []byte, epoch uint64) ([]byte, error) {
	k3Outer, hkdfContext, err := deriveSprpKey(type3Message, sharedRandomValue, epoch, c.sharedEpochKey.Bytes())
	if err != nil {
		return nil, err
	}

	dh := [32]byte{}
	c.keypair2.Private().Exp(&dh, beta2)

	salt := getSalt(sharedRandomValue, epoch)
	prk3i := hkdf.Extract(HashFunc, dh[:], salt)
	kdfReader := hkdf.Expand(HashFunc, prk3i, hkdfContext)
	k3Inner := [SPRPKeyLength]byte{}
	_, err = kdfReader.Read(k3Inner[:])
	if err != nil {
		return nil, err
	}

	k3InnerIV := [SPRPIVLength]byte{}
	k3OuterIV := [SPRPIVLength]byte{}
	t3 := SPRPEncrypt(k3Outer, &k3OuterIV, SPRPEncrypt(&k3Inner, &k3InnerIV, c.sessionKey2.Bytes()))
	return t3, nil
}

func (c *Client) ProcessType3Message(t3, gamma []byte, beta2 *PublicKey, epoch uint64, sharedRandomValue []byte) ([]byte, error) {
	k3Outer, hkdfContext, err := deriveSprpKey(type3Message, sharedRandomValue, epoch, c.sharedEpochKey.Bytes())
	if err != nil {
		return nil, err
	}

	dh := [32]byte{}
	c.keypair2.Private().Exp(&dh, beta2)

	salt := getSalt(sharedRandomValue, epoch)
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

func (c *Client) Marshal() ([]byte, error) {
	var serialized []byte
	cc := clientCbor{
		Keypair1:       c.keypair1,
		Keypair2:       c.keypair2,
		SessionKey1:    c.sessionKey1.Bytes(),
		SessionKey2:    c.sessionKey2.Bytes(),
		SharedEpochKey: c.sharedEpochKey.Bytes(),
	}
	err := codec.NewEncoderBytes(&serialized, cborHandle).Encode(&cc)
	if err != nil {
		return nil, err
	}
	return serialized, nil
}

func (c *Client) Unmarshal(data []byte) error {
	return codec.NewDecoderBytes(data, cborHandle).Decode(c)
}
