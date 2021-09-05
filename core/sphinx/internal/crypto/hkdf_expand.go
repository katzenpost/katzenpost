// hkdf_expand.go - HKDF-Expand.
// Copyright (C) 2015  Yawning Angel.
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
	"crypto/hmac"
	"hash"

	"github.com/katzenpost/core/utils"
)

func hkdfExpand(hashFn func() hash.Hash, prk []byte, info []byte, l int) []byte {
	// Why, yes.  golang.org/x/crypto/hkdf exists, and is a fine
	// implementation of HKDF.  However it does both the extract
	// and expand, with no way to separate the two steps.

	h := hmac.New(hashFn, prk)
	defer h.Reset()
	digestSz := h.Size()
	if l > 255*digestSz {
		panic("hkdf: requested OKM length > 255*HashLen")
	}

	var t []byte
	defer utils.ExplicitBzero(t)
	okm := make([]byte, 0, l)
	toAppend := l
	ctr := byte(1)
	for toAppend > 0 {
		h.Reset()
		h.Write(t)
		h.Write(info)
		h.Write([]byte{ctr})
		t = h.Sum(nil)
		ctr++

		aLen := digestSz
		if toAppend < digestSz {
			aLen = toAppend
		}
		okm = append(okm, t[:aLen]...)
		toAppend -= aLen
	}
	return okm
}
