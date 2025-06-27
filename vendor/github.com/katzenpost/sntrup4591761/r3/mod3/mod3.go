// Copyright (c) 2017 Company 0 LLC. All rights reserved.
// Use of this source code is governed by an ISC-style
// license that can be found in the LICENSE file.

// This file implements selected arithmetic operations over GF(3). It is
// a port of the public domain, C reference implementation.

package mod3

func Freeze(a int32) int8 {
	a -= 3 * ((10923 * a) >> 15)
	a -= 3 * ((89478485*a + 134217728) >> 28)
	return int8(a)
}

func Product(a, b int8) int8 {
	return a * b
}

func Reciprocal(a int8) int8 {
	return a
}

func Quotient(a, b int8) int8 {
	return Product(a, Reciprocal(b))
}

func MinusProduct(a, b, c int8) int8 {
	A := int32(a)
	B := int32(b)
	C := int32(c)
	return Freeze(A - B*C)
}

func PlusProduct(a, b, c int8) int8 {
	A := int32(a)
	B := int32(b)
	C := int32(c)
	return Freeze(A + B*C)
}

func Sum(a, b int8) int8 {
	A := int32(a)
	B := int32(b)
	return Freeze(A + B)
}

func MaskSet(x int8) int {
	return int(-x * x)
}
