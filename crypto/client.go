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

	"github.com/katzenpost/core/crypto/rand"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

type Client struct {
	keypair1       *Keypair
	keypair2       *Keypair
	k1             *[SPRPKeyLength]byte
	k1Counter      uint64
	s1             *[32]byte
	s2             *[32]byte
	passphrase     []byte
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
	// XXX t := uint32(9001)
	t := uint32(1)
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
	crs := getCommonReferenceString(sharedRandomValue, epoch)

	k1, err := kdf(crs, c.passphrase, epoch)
	if err != nil {
		return nil, err
	}
	c.k1 = &[SPRPKeyLength]byte{}
	copy(c.k1[:], k1)
	key := [SPRPKeyLength]byte{}
	copy(key[:], k1)
	iv := [SPRPIVLength]byte{}
	binary.BigEndian.PutUint64(iv[:], c.k1Counter)
	alpha := SPRPEncrypt(&key, &iv, keypair1ElligatorPub[:])

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

func (c *Client) Type2MessageFromType1(message []byte, sharedRandomValue []byte, epoch uint64) ([]byte, error) {
	alpha, _, _, err := decodeT1Message(message)
	if err != nil {
		return nil, err
	}

	iv := [SPRPIVLength]byte{}
	binary.BigEndian.PutUint64(iv[:], c.k1Counter)
	elligatorPub1 := SPRPDecrypt(c.k1, &iv, alpha)

	rKey := [RepresentativeLength]byte{}
	copy(rKey[:], elligatorPub1)
	r := Representative(rKey)
	b1PubKey := r.ToPublic()

	// hkdf_context = "type 2" || EpochID
	hkdfContext := []byte("Type-2")
	var tmp [8]byte
	binary.BigEndian.PutUint64(tmp[:], epoch)
	hkdfContext = append(hkdfContext, tmp[:]...)

	crs := getCommonReferenceString(sharedRandomValue, epoch)
	prk2 := hkdf.Extract(HashFunc, c.sharedEpochKey, crs)
	kdfReader := hkdf.Expand(HashFunc, prk2, hkdfContext)
	k2Outer := [SPRPKeyLength]byte{}
	_, err = kdfReader.Read(k2Outer[:])
	if err != nil {
		return nil, err
	}

	k2idh := [32]byte{}
	c.keypair1.Private().Exp(&k2idh, b1PubKey)

	kdfReader = hkdf.Expand(HashFunc, k2idh[:], crs)
	k2Inner := [SPRPKeyLength]byte{}
	_, err = kdfReader.Read(k2Inner[:])
	if err != nil {
		return nil, err
	}

	// XXX correct?
	k2InnerIV := [SPRPIVLength]byte{}
	k2OuterIV := [SPRPIVLength]byte{}
	t2 := SPRPEncrypt(&k2Outer, &k2OuterIV, SPRPEncrypt(&k2Inner, &k2InnerIV, c.s1[:]))
	return t2, nil
}
