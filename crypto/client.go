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
	"github.com/katzenpost/core/crypto/rand"
)

type Client struct {
	k1         *Keypair
	k2         *Keypair
	s1         *[32]byte
	s2         *[32]byte
	passphrase []byte
}

func NewClient(passphrase []byte) (*Client, error) {
	keypair1, err := NewKeypair(true)
	if err != nil {
		return nil, err
	}
	keypair2, err := NewKeypair(true)
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
	client := &Client{
		k1:         keypair1,
		k2:         keypair2,
		s1:         &s1,
		s2:         &s2,
		passphrase: passphrase,
	}
	return client, nil
}

func (c *Client) GenerateType1Message(epoch uint64, sharedRandomValue, payload []byte) ([]byte, error) {
	k1ElligatorPub := c.k1.Representative().ToPublic().Bytes()
	alpha, err := newT1Alpha(epoch, sharedRandomValue, c.passphrase, k1ElligatorPub)
	if err != nil {
		return nil, err
	}
	beta, err := newT1Beta(c.k2.Public().Bytes(), c.s1)
	if err != nil {
		return nil, err
	}
	gamma, err := newT1Gamma(payload, c.s2)
	if err != nil {
		return nil, err
	}
	output := []byte{}
	output = append(output, alpha...)
	output = append(output, beta...)
	output = append(output, gamma...)
	return output, nil
}

func (c *Client) Type2MessageFromType1(message []byte) ([]byte, error) {
	return nil, nil // XXX
}
