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
	"encoding/binary"
	"fmt"

	"github.com/katzenpost/core/crypto/rand"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

type Client struct {
	keypair1       *Keypair
	keypair2       *Keypair
	k1             *[SPRPKeyLength]byte
	k1Counter      uint64 // XXX when to increment?
	s1             *[32]byte
	s2             *[32]byte
	sharedEpochKey []byte
}

func NewClient(passphrase []byte, sharedRandomValue []byte, epoch uint64) (*Client, error) {
	keypair1, err := NewKeypair(true)
	if err != nil {
		return nil, err
	}
	keypair2, err := NewKeypair(false)
	if err != nil {
		return nil, err
	}
	s1 := [32]byte{}
	_, err = rand.Reader.Read(s1[:])
	if err != nil {
		return nil, err
	}
	s2 := [32]byte{}
	_, err = rand.Reader.Read(s2[:])
	if err != nil {
		return nil, err
	}

	crs := getCommonReferenceString(sharedRandomValue, epoch)
	salt := crs
	// XXX t := uint32(9001) // XXX are you sure you want it set this big?
	t := uint32(1) // testing value to speed things up
	memory := uint32(9001)
	threads := uint8(1)
	keyLen := uint32(32)

	client := &Client{
		keypair1:       keypair1,
		keypair2:       keypair2,
		s1:             &s1,
		s2:             &s2,
		sharedEpochKey: argon2.IDKey(passphrase, salt, t, memory, threads, keyLen),
	}
	return client, nil
}

func (c *Client) GenerateType1Message(epoch uint64, sharedRandomValue, payload []byte) ([]byte, error) {
	keypair1ElligatorPub := c.keypair1.Representative().ToPublic().Bytes()
	fmt.Printf("><><><><><><><><>< keypair1.public_key %x\n", c.keypair1.Public().Bytes())

	k1, err := deriveT1SprpKey(sharedRandomValue, epoch, c.sharedEpochKey)
	if err != nil {
		return nil, err
	}
	c.k1 = k1
	iv := [SPRPIVLength]byte{}
	binary.BigEndian.PutUint64(iv[:], c.k1Counter)
	alpha := SPRPEncrypt(k1, &iv, keypair1ElligatorPub[:])

	beta, err := newT1Beta(c.keypair2.Public().Bytes(), c.s1)
	if err != nil {
		return nil, err
	}

	gamma, err := newT1Gamma(payload[:], c.s2)
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

	k1, err := deriveT1SprpKey(sharedRandomValue, epoch, c.sharedEpochKey)
	if err != nil {
		return nil, nil, err
	}

	iv := [SPRPIVLength]byte{}
	binary.BigEndian.PutUint64(iv[:], c.k1Counter)
	elligatorPub1 := SPRPDecrypt(k1, &iv, alpha)

	rKey := [RepresentativeLength]byte{}
	copy(rKey[:], elligatorPub1)
	r := Representative(rKey)
	b1PubKey := r.ToPublic()

	fmt.Printf("><><><><><><><><>< Decrypted un-elligatored key: %x\n", *b1PubKey)

	k2Outer, hkdfContext, err := deriveOuterSPRPKey(sharedRandomValue, epoch, c.sharedEpochKey)
	if err != nil {
		return nil, nil, err
	}

	k2idh := [32]byte{}
	c.keypair1.Private().Exp(&k2idh, b1PubKey)

	crs := getCommonReferenceString(sharedRandomValue, epoch)
	prk2i := hkdf.Extract(HashFunc, k2idh[:], crs)
	kdfReader := hkdf.Expand(HashFunc, prk2i, hkdfContext)
	k2Inner := [SPRPKeyLength]byte{}
	_, err = kdfReader.Read(k2Inner[:])
	if err != nil {
		return nil, nil, err
	}

	k2InnerIV := [SPRPIVLength]byte{}
	k2OuterIV := [SPRPIVLength]byte{}
	t2 := SPRPEncrypt(k2Outer, &k2OuterIV, SPRPEncrypt(&k2Inner, &k2InnerIV, c.s1[:]))
	return t2, b1PubKey, nil
}

func (c *Client) GetCandidateKey(t2 []byte, alpha *PublicKey, epoch uint64, sharedRandomValue []byte) ([]byte, error) {
	k3Outer, hkdfContext, err := deriveOuterSPRPKey(sharedRandomValue, epoch, c.sharedEpochKey)
	if err != nil {
		return nil, err
	}

	// DH operation
	k3idh := [32]byte{}
	c.keypair1.Private().Exp(&k3idh, alpha)

	// HKDF extract and expand
	crs := getCommonReferenceString(sharedRandomValue, epoch)
	prk3i := hkdf.Extract(HashFunc, k3idh[:], crs)

	kdfReader := hkdf.Expand(HashFunc, prk3i, hkdfContext)
	k3Inner := [SPRPKeyLength]byte{}
	_, err = kdfReader.Read(k3Inner[:])
	if err != nil {
		return nil, err
	}

	k3InnerIV := [SPRPIVLength]byte{}
	k3OuterIV := [SPRPIVLength]byte{}
	return SPRPDecrypt(k3Outer, &k3OuterIV, SPRPDecrypt(&k3Inner, &k3InnerIV, t2)), nil
}
