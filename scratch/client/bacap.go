// bacap.go - scratch service client bacap helpers
// Copyright (C) 2025  Masala
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

package client

import (
	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/hpqc/sign/ed25519"
)

// Make a new BoxOwnerCap with a ed25519.SecretKey and a seed
func NewOwnerCapFromSeed(sK *ed25519.PrivateKey, seed []byte) *bacap.BoxOwnerCap {
	rr, err := rand.NewDeterministicRandReader(seed)
	if err != nil {
		panic(err)
	}
	mbi, err := bacap.NewMessageBoxIndex(rr)
	if err != nil {
		panic(err)
	}
	rawmbi, err := mbi.MarshalBinary()
	if err != nil {
		panic(err)
	}
	data := append(sK.Bytes(), rawmbi...)
	c := &bacap.BoxOwnerCap{}
	c.UnmarshalBinary(data)
	return c
}

// Make a new UniversalReadCap with a ed25519.PublicKey and a seed
func NewUniversalReadCapFromSeed(pK *ed25519.PublicKey, seed []byte) *bacap.UniversalReadCap {
	rr, err := rand.NewDeterministicRandReader(seed)
	if err != nil {
		panic(err)
	}
	mbi, err := bacap.NewMessageBoxIndex(rr)
	if err != nil {
		panic(err)
	}
	rawmbi, err := mbi.MarshalBinary()
	if err != nil {
		panic(err)
	}
	data := append(pK.Bytes(), rawmbi...)
	c, err := bacap.UniversalReadCapFromBinary(data)
	if err != nil {
		panic(err)
	}
	return c
}
