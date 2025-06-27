// Copyright (c) 2017 Company 0 LLC. All rights reserved.
// Use of this source code is governed by an ISC-style
// license that can be found in the LICENSE file.

// These routines are a port of the public domain, C reference implementation.

package vector

import (
	"github.com/katzenpost/sntrup4591761/rq/modq"
)

// Swap swaps x and y if mask is -1. If mask is 0, x and y retain
// their original values.
func Swap(x, y []int16, bytes, mask int) {
	c := int16(mask)
	for i := 0; i < bytes; i++ {
		t := c & (x[i] ^ y[i])
		x[i] ^= t
		y[i] ^= t
	}
}

func Product(z []int16, n int, x []int16, c int16) {
	for i := 0; i < n; i++ {
		z[i] = modq.Product(x[i], c)
	}
}

func MinusProduct(z []int16, n int, x, y []int16, c int16) {
	for i := 0; i < n; i++ {
		z[i] = modq.MinusProduct(x[i], y[i], c)
	}
}

func Shift(z []int16, n int) {
	for i := n - 1; i > 0; i-- {
		z[i] = z[i-1]
	}
	z[0] = 0
}
