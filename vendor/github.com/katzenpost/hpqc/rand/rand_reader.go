// rand_reader.go - `crypto/rand.Reader` replacement
// Copyright (C) 2016  Yawning Angel.
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

package rand

import (
	"io"

	"github.com/katzenpost/hpqc/util"
	"golang.org/x/crypto/blake2b"
)

// At least as of Go 1.6.1,  Go's crypto/rand does some horrific bullshit that
// defeats the point of getrandom(2), namedly, it cowardly refuses to use the
// syscall based entropy source if it would have blocked on the first call.
//
// This is rather suboptimal.  The correct thing to do for something named
// "crypto/rand" is to fucking BLOCK if the entropy pool isn't there and not
// to pull poor quality entropy by falling back to doing blocking reads on
// "/dev/urandom".
//
// This was brought up in https://github.com/golang/go/issues/11833
// and dismissed, I think they're wrong, I'm fixing it on common systems
// that I care about.
//
// Upstream has seen the errors of their ways and fixed this as of Go 1.9
// (See: https://github.com/golang/go/issues/19274), but that isn't guaranteed
// to be everywhere, and there's an advantage to whitening the output anyway.

const xofEntropySize = 32

var (
	// Reader is a replacement for crypto/rand.Reader.
	Reader io.Reader

	usingImprovedSyscallEntropy = false
	xofKey                      [xofEntropySize]byte
)

type nonShitRandReader struct {
	getentropyFn func([]byte) error
}

func (r *nonShitRandReader) Read(b []byte) (int, error) {
	blen := len(b)
	switch {
	case blen == 0:
		return 0, nil
	}

	// Whiten the output using BLAKE2Xb.
	var xofEntropy [xofEntropySize]byte
	xof, err := blake2b.NewXOF(uint32(len(b)), xofKey[:])
	if err != nil {
		return 0, err
	}
	defer func() {
		xof.Reset()
		util.ExplicitBzero(xofEntropy[:])
	}()
	if err := r.getentropyFn(xofEntropy[:]); err != nil {
		return 0, err
	}
	if _, err := xof.Write(xofEntropy[:]); err != nil {
		return 0, err
	}
	return xof.Read(b)
}

func initWhitening() {
	if _, err := Reader.Read(xofKey[:]); err != nil {
		panic("BUG: failed to initialize XOF key: " + err.Error())
	}
}
