// Copyright (c) 2017 Company 0 LLC. All rights reserved.
// Use of this source code is governed by an ISC-style
// license that can be found in the LICENSE file.

// These routines are a port of the public domain, C reference implementation.

package zx

import (
	"crypto/subtle"
	"io"
)

// random32 returns a random int32 obtained from s.
func random32(s io.Reader) (int32, error) {
	b := new([4]byte)
	_, err := io.ReadFull(s, b[:])
	if err != nil {
		return 0, err
	}
	r := int32(0)
	for i := uint(0); i < 4; i++ {
		r += int32(b[i]) << (8 * i)
	}
	return r, nil
}

// minmax swaps x[0] and y[0] if y[0] < x[0].
func minmax(x, y []int32) {
	xi := int(uint32(x[0]))
	yi := int(uint32(y[0]))
	s := subtle.ConstantTimeLessOrEq(yi, xi)
	x[0] = int32(subtle.ConstantTimeSelect(s, yi, xi))
	y[0] = int32(subtle.ConstantTimeSelect(s, xi, yi))
}

func sort(x []int32, n int) {
	if n < 2 {
		return
	}
	top := 1
	for top < n-top {
		top += top
	}
	for p := top; p > 0; p >>= 1 {
		for i := 0; i < n-p; i++ {
			if (i & p) == 0 {
				minmax(x[i:], x[(i+p):])
			}
		}
		for q := top; q > p; q >>= 1 {
			for i := 0; i < n-q; i++ {
				if (i & p) == 0 {
					minmax(x[(i+p):], x[(i+q):])
				}
			}
		}
	}
}

// RandomSmall returns a random small element of R. An element
// of R is small if all of its coefficients are in {-1,0,1}.
// Randomness is obtained from s.
func RandomSmall(g *[761]int8, s io.Reader) error {
	for i := 0; i < 761; i++ {
		r, err := random32(s)
		if err != nil {
			return err
		}
		g[i] = int8((((1073741823 & uint32(r)) * 3) >> 30)) - 1
	}
	return nil
}

// RandomTSmall returns a random t-small element of R. An element
// of R is t-small if exactly 2*t of its coefficients are nonzero.
// Randomness is obtained from s.
func RandomTSmall(f *[761]int8, s io.Reader) error {
	r := new([761]int32)
	for i := 0; i < 761; i++ {
		x, err := random32(s)
		if err != nil {
			return err
		}
		r[i] = x
	}
	for i := 0; i < 286; i++ {
		r[i] &= -2
	}
	for i := 286; i < 761; i++ {
		r[i] = (r[i] & -3) | 1
	}
	sort(r[:], 761)
	for i := 0; i < 761; i++ {
		f[i] = int8(r[i]&3) - 1
	}
	return nil
}
