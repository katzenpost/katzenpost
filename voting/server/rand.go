// rand.go -
// Copyright (C) 2018  David Stainton.
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

package server

import (
	"encoding/binary"
	"math/rand"

	"git.schwanenlied.me/yawning/chacha20"
)

type DeterministicRandReader struct {
	cipher *chacha20.Cipher
	key    []byte
}

func NewDeterministicRandReader(key []byte) (*DeterministicRandReader, error) {
	var nonce [8]byte
	cipher, err := chacha20.NewCipher(key, nonce[:])
	if err != nil {
		return nil, err
	}
	reader := DeterministicRandReader{
		cipher: cipher,
		key:    key,
	}
	return &reader, err
}

func (r *DeterministicRandReader) Read(data []byte) (int, error) {
	readLen := len(data)
	r.cipher.KeyStream(data)
	return readLen, nil
}

func (s *DeterministicRandReader) Int63() int64 {
	tmp := [8]byte{}
	_, err := s.Read(tmp[:])
	if err != nil {
		panic(err)
	}
	// gotta chop those sign bits!
	tmp[7] = tmp[7] & 0x7F
	return int64(binary.LittleEndian.Uint64(tmp[:]))
}

func (s *DeterministicRandReader) Seed(seed int64) {
	var nonce [8]byte
	var err error
	count := binary.PutUvarint(nonce[:], uint64(seed))
	if int64(count) != seed {
		panic("wtf")
	}
	s.cipher, err = chacha20.NewCipher(s.key, nonce[:])
	if err != nil {
		panic(err)
	}
}

func (s *DeterministicRandReader) Perm(n int) []int {
	r := rand.New(s)
	return r.Perm(n)
}
