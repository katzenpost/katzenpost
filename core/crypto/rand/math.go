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

	"github.com/katzenpost/chacha20"
	"github.com/katzenpost/katzenpost/core/utils"
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
	if s.s.ReKey(seed[:], mNonce[:]) != nil {
		panic("chacha20 ReKey failed, not expected.")
	}
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
	if err := s.s.ReKey(seed[:], mNonce[:]); err != nil {
		panic("s.s.ReKey(chacha20) failed, not expected")
	}
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

	return r.ExpFloat64() / lambda
}

// ExpQuantile returns the value at which the the probability of a random value
// is less than or equal to the given probability for an exponential
// distribution characterized by lambda.
func ExpQuantile(lambda, p float64) float64 {
	if lambda < math.SmallestNonzeroFloat64 {
		panic("crypto/rand: lambda out of range")
	}
	if p < math.SmallestNonzeroFloat64 || p >= 1.0 {
		panic("crypto/rand: p out of range")
	}

	return -math.Log(1-p) / lambda
}

// Poisson returns a random sample from the poisson distribution characterized
// by lambda (mean).
func Poisson(r *rand.Rand, lambda float64) int {
	if lambda < 30.0 {
		return poissonSmall(r, lambda)
	}
	return poissonLarge(r, lambda)
}

func poissonSmall(r *rand.Rand, lambda float64) int {
	// Algorithm due to Donald Knuth, 1969.
	p, l := float64(1.0), math.Exp(-lambda)
	k := 0
	for {
		if s := r.Float64(); s > 0.0 {
			k++
			p = p * s
		}
		if p <= l {
			break
		}
	}
	return k - 1
}

func poissonLarge(r *rand.Rand, lambda float64) int {
	// "Rejection method PA" from "The Computer Generation of
	// Poisson Random Variables" by A. C. Atkinson,
	// Journal of the Royal Statistical Society Series C
	// (Applied Statistics) Vol. 28, No. 1. (1979)
	// The article is on pages 29-35.
	// The algorithm given here is on page 32.

	c := 0.767 - 3.36/lambda
	beta := math.Pi / math.Sqrt(3.0*lambda)
	alpha := beta * lambda
	k := math.Log(c) - lambda - math.Log(beta)

	for {
		u := r.Float64()
		if u == 0.0 {
			continue
		}
		x := (alpha - math.Log((1.0-u)/u)) / beta
		n := math.Floor(x + 0.5)
		if n < 0 {
			continue
		}
		v := r.Float64()
		if v == 0.0 {
			continue
		}
		y := alpha - beta*x
		temp := 1.0 + math.Exp(y)
		lhs := y + math.Log(v/(temp*temp))
		rhs := k + n*math.Log(lambda) - logFactorial(n)
		if lhs <= rhs {
			return int(n)
		}
	}
}

func logFactorial(n float64) float64 {
	// Use Stirling's approximation, since the runtime library has
	// the gamma function math.
	n = math.Floor(n)
	ret, _ := math.Lgamma(n + 1)
	return ret
}
