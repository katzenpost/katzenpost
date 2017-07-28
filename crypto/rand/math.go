// math.go - math/rand replacement.
// Copyright (C) 2017  Yawning Angel.
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

// Package rand provides various utitilies related to generating
// cryptographically secure random numbers and byte vectors.
package rand

import (
	"encoding/binary"
	"io"
	"math"
	"math/rand"
	"sync"

	"git.schwanenlied.me/yawning/chacha20.git"
	"github.com/katzenpost/core/utils"
)

const seedSize = chacha20.KeySize

var mNonce [chacha20.NonceSize]byte

type randSource struct {
	sync.Mutex
	s   *chacha20.Cipher
	off int
}

func (s *randSource) feedForward() {
	var seed [chacha20.KeySize]byte
	defer utils.ExplicitBzero(seed[:])
	s.s.KeyStream(seed[:])
	s.s.ReKey(seed[:], mNonce[:])
	s.off = 0
}

func (s *randSource) Uint64() uint64 {
	s.Lock()
	defer s.Unlock()

	if s.off+8 > chacha20.BlockSize-seedSize {
		s.feedForward()
	}

	s.off += 8

	var tmp [8]byte
	s.s.KeyStream(tmp[:])
	return binary.LittleEndian.Uint64(tmp[:])
}

func (s *randSource) Int63() int64 {
	ret := s.Uint64()
	return int64(ret & ((1 << 63) - 1))
}

func (s *randSource) Seed(unused int64) {
	var seed [chacha20.KeySize]byte
	defer utils.ExplicitBzero(seed[:])
	if _, err := io.ReadFull(Reader, seed[:]); err != nil {
		panic("crypto/rand: failed to read entropy: " + err.Error())
	}
	s.s.ReKey(seed[:], mNonce[:])
	s.off = 0
}

// NewMath returns a "cryptographically secure" math/rand.Rand.
func NewMath() *rand.Rand {
	s := new(randSource)
	s.s = new(chacha20.Cipher)
	s.Seed(0)
	return rand.New(s)
}

// Exp returns a random sample from the exponential distribution characterized
// by lambda (inverse of the mean).
func Exp(r *rand.Rand, lambda float64) float64 {
	if lambda < math.SmallestNonzeroFloat64 {
		panic("crypto/rand: lambda out of range")
	}
	return (-1.0 / lambda) * math.Log(r.Float64())
}
