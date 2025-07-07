// Copyright (c) 2017 Company 0 LLC. All rights reserved.
// Use of this source code is governed by an ISC-style
// license that can be found in the LICENSE file.

// This file implements operations in Rq, a univariate quotient polynomial
// ring over GF(q) with modulus x^761 + 4590*x + 4590. It is a port of the
// public domain, C reference implementation.

package rq

import (
	"github.com/katzenpost/sntrup4591761/rq/modq"
	"github.com/katzenpost/sntrup4591761/rq/vector"
)

// swapInt swaps x and y if mask is -1. If mask is 0, x and y retain
// their original values.
func swapInt(x, y *int, mask int) {
	t := mask & (*x ^ *y)
	*x ^= t
	*y ^= t
}

// smallerMask compares x and y, returning -1 if y > x, and 0 otherwise.
func smallerMask(x, y int) int {
	return (x - y) >> 31
}

// Reciprocal produces the inverse r of a polynomial 3*s in Rq.
// If s is not invertible, Reciprocal returns -1, and 0 otherwise.
func Reciprocal3(r *[761]int16, s *[761]int8) int {
	// f starts as the modulus of Rq.
	f := new([761 + 1]int16)
	f[0] = -1
	f[1] = -1
	f[761] = 1

	// g starts as 3*s
	g := new([761 + 1]int16)
	for i := 0; i < 761; i++ {
		g[i] = int16(3 * s[i])
	}

	d := 761
	e := 761
	loops := 2*761 + 1
	u := make([]int16, loops+1)
	v := make([]int16, loops+1)
	v[0] = 1

	for i := 0; i < loops; i++ {
		// c = (lc(g)/lc(f)) % 3
		c := modq.Quotient(g[761], f[761])
		// g = g - f*c; g <<= 1
		vector.MinusProduct(g[:], 761+1, g[:], f[:], c)
		vector.Shift(g[:], 761+1)
		// v = v - u*c
		vector.MinusProduct(v, loops+1, v, u, c)
		vector.Shift(v, loops+1)
		// swap (e,d), (f,g), and (u,v) if d > e and lc(g) != 0
		e--
		m := smallerMask(e, d) & modq.MaskSet(g[761])
		swapInt(&e, &d, m)
		vector.Swap(f[:], g[:], 761+1, m)
		vector.Swap(u, v, loops+1, m)
	}
	vector.Product(r[:], 761, u[761:], modq.Reciprocal(f[761]))

	return smallerMask(0, d)
}

func Round3(h, f *[761]int16) {
	for i := 0; i < 761; i++ {
		h[i] = int16(((21846*int32(f[i]+2295)+32768)>>16)*3 - 2295)
	}
}

// Mult returns the product h of f and g in Rq.
func Mult(h, f *[761]int16, g *[761]int8) {
	fg := new([761*2 - 1]int16)
	for i := 0; i < 761; i++ {
		r := int16(0)
		for j := 0; j <= i; j++ {
			r = modq.PlusProduct(r, f[j], int16(g[i-j]))
		}
		fg[i] = r
	}
	for i := 761; i < 761*2-1; i++ {
		r := int16(0)
		for j := i - 761 + 1; j < 761; j++ {
			r = modq.PlusProduct(r, f[j], int16(g[i-j]))
		}
		fg[i] = r
	}
	for i := 761*2 - 2; i >= 761; i-- {
		fg[i-761] = modq.Sum(fg[i-761], fg[i])
		fg[i-761+1] = modq.Sum(fg[i-761+1], fg[i])
	}
	for i := 0; i < 761; i++ {
		h[i] = fg[i]
	}
}
