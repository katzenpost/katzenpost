// Copyright (c) 2017 Company 0 LLC. All rights reserved.
// Use of this source code is governed by an ISC-style
// license that can be found in the LICENSE file.

// This file implements selected arithmetic operations over GF(q). It is
// a port of the public domain, C reference implementation.

package modq

func Freeze(a int32) int16 {
	a -= 4591 * ((228 * a) >> 20)
	a -= 4591 * ((58470*a + 134217728) >> 28)
	return int16(a)
}

func Product(a, b int16) int16 {
	A := int32(a)
	B := int32(b)
	return Freeze(A * B)
}

func Square(a int16) int16 {
	A := int32(a)
	return Freeze(A * A)
}

func Reciprocal(a1 int16) int16 {
	a2 := Square(a1)
	a3 := Product(a2, a1)
	a4 := Square(a2)
	a8 := Square(a4)
	a16 := Square(a8)
	a32 := Square(a16)
	a35 := Product(a32, a3)
	a70 := Square(a35)
	a140 := Square(a70)
	a143 := Product(a140, a3)
	a286 := Square(a143)
	a572 := Square(a286)
	a1144 := Square(a572)
	a1147 := Product(a1144, a3)
	a2294 := Square(a1147)
	a4588 := Square(a2294)
	a4589 := Product(a4588, a1)
	return a4589
}

func Quotient(a, b int16) int16 {
	return Product(a, Reciprocal(b))
}

func MinusProduct(a, b, c int16) int16 {
	A := int32(a)
	B := int32(b)
	C := int32(c)
	return Freeze(A - B*C)
}

func PlusProduct(a, b, c int16) int16 {
	A := int32(a)
	B := int32(b)
	C := int32(c)
	return Freeze(A + B*C)
}

func Sum(a, b int16) int16 {
	A := int32(a)
	B := int32(b)
	return Freeze(A + B)
}

func MaskSet(x int16) int {
	r := int32(uint16(x))
	r = -r
	r >>= 30
	return int(r)
}
