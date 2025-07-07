// Copyright (c) 2017 Company 0 LLC. All rights reserved.
// Use of this source code is governed by an ISC-style
// license that can be found in the LICENSE file.

// This file implements operations in R3, a univariate quotient polynomial
// ring over GF(3) with modulus x^761 + 2*x + 2. It is a port of the public
// domain, C reference implementation.

package r3

import (
	"github.com/katzenpost/sntrup4591761/r3/mod3"
	"github.com/katzenpost/sntrup4591761/r3/vector"
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

// Reciprocal produces the inverse r of a polynomial s in R3.
// If s is not invertible, Reciprocal returns -1, and 0 otherwise.
func Reciprocal(r, s *[761]int8) int {
	// f starts as the modulus of R3.
	f := new([761 + 1]int8)
	f[0] = -1
	f[1] = -1
	f[761] = 1

	// g starts as s.
	g := new([761 + 1]int8)
	for i := 0; i < 761; i++ {
		g[i] = s[i]
	}

	d := 761
	e := 761
	loops := 2*761 + 1
	u := make([]int8, loops+1)
	v := make([]int8, loops+1)
	v[0] = 1

	for i := 0; i < loops; i++ {
		// c = (lc(g)/lc(f)) % 3
		c := mod3.Quotient(g[761], f[761])
		// g = g - f*c; g <<= 1
		vector.MinusProduct(g[:], 761+1, g[:], f[:], c)
		vector.Shift(g[:], 761+1)
		// v = v - u*c
		vector.MinusProduct(v, loops+1, v, u, c)
		vector.Shift(v, loops+1)
		// swap (e,d), (f,g), and (u,v) if d > e and lc(g) != 0
		e--
		m := smallerMask(e, d) & mod3.MaskSet(g[761])
		swapInt(&e, &d, m)
		vector.Swap(f[:], g[:], 761+1, m)
		vector.Swap(u, v, loops+1, m)
	}
	vector.Product(r[:], 761, u[761:], mod3.Reciprocal(f[761]))

	return smallerMask(0, d)
}

// Mult returns the product h of f and g in R3.
func Mult(h, f, g *[761]int8) {
	fg := new([761*2 - 1]int8)
	for i := 0; i < 761; i++ {
		r := int8(0)
		for j := 0; j <= i; j++ {
			r = mod3.PlusProduct(r, f[j], g[i-j])
		}
		fg[i] = r
	}
	for i := 761; i < 761*2-1; i++ {
		r := int8(0)
		for j := i - 761 + 1; j < 761; j++ {
			r = mod3.PlusProduct(r, f[j], g[i-j])
		}
		fg[i] = r
	}
	for i := 761*2 - 2; i >= 761; i-- {
		fg[i-761] = mod3.Sum(fg[i-761], fg[i])
		fg[i-761+1] = mod3.Sum(fg[i-761+1], fg[i])
	}
	for i := 0; i < 761; i++ {
		h[i] = fg[i]
	}
}
