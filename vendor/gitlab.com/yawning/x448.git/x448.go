// The MIT License (MIT)
//
// Copyright (c) 2014-2015 Cryptography Research, Inc.
// Copyright (c) 2015-2019 Yawning Angel.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

// Package x448 provides an implementation of scalar multiplication on the
// elliptic curve known as curve448.
//
// See https://www.rfc-editor.org/rfc/rfc7748.txt
package x448

import (
	"gitlab.com/yawning/x448.git/internal/field"
	_ "gitlab.com/yawning/x448.git/internal/toolchain"
)

const (
	x448Bytes = 56
	edwardsD  = -39081
)

var (
	basePoint = [x448Bytes]byte{5}

	feOne  = field.TightFieldElement{1}
)

func ScalarMult(out, scalar, base *[56]byte) {
	var (
		x1, x2, z2, x3, z3 field.TightFieldElement
		t1, t2             field.LooseFieldElement
	)
	field.FromBytes(&x1, base)
	field.Set(&x2, &feOne)
	// z2 = 0
	field.Set(&x3, &x1)
	field.Set(&z3, &feOne)

	var swap field.LimbUint

	for t := int(448 - 1); t >= 0; t-- {
		sb := scalar[t/8]

		// Scalar conditioning.
		if t/8 == 0 {
			sb &= 0xFC
		} else if t/8 == x448Bytes-1 {
			sb |= 0x80
		}

		kT := (field.LimbUint)((sb >> ((uint)(t) % 8)) & 1)
		kT = -kT // Set to all 0s or all 1s

		swap ^= kT
		field.CondSwap(&x2, &x3, swap)
		field.CondSwap(&z2, &z3, swap)
		swap = kT

		// Note: This deliberately omits reductions after add/sub operations
		// if the result is only ever used as the input to a mul/sqr since
		// the implementations of those can deal with non-reduced inputs,
		// or in the case of the 32-bit implementation, add/sub will never
		// return non-reduced outputs.
		//
		// field.UnsafeTightenCast is only used to store a fully reduced
		// output in a LooseFieldElement, or to provide such a
		// LooseFieldElement as a TightFieldElement argument.
		field.Add(&t1, &x2, &z2)                                        // A = x2 + z2
		field.Sub(&t2, &x2, &z2)                                        // B = x2 - z2
		field.Sub(field.RelaxCast(&z2), &x3, &z3)                       // D = x3 - z3 (z2 unreduced)
		field.CarryMul(&x2, &t1, field.RelaxCast(&z2))                  // DA
		field.Add(field.RelaxCast(&z2), &x3, &z3)                       // C = x3 + z3 (z2 unreduced)
		field.CarryMul(&x3, &t2, field.RelaxCast(&z2))                  // CB
		field.Sub(field.RelaxCast(&z3), &x2, &x3)                       // DA-CB (z3 unreduced)
		field.CarrySquare(&z2, field.RelaxCast(&z3))                    // (DA-CB)^2 (z2 reduced)
		field.CarryMul(&z3, field.RelaxCast(&x1), field.RelaxCast(&z2)) // z3 = x1(DA-CB)^2 (z3 reduced)
		field.Add(field.RelaxCast(&z2), &x2, &x3)                       // (DA+CB) (z2 unreduced)
		field.CarrySquare(&x3, field.RelaxCast(&z2))                    // x3 = (DA+CB)^2

		field.CarrySquare(&z2, &t1)                          // AA = A^2 (z2 reduced)
		field.CarrySquare(field.UnsafeTightenCast(&t1), &t2) // BB = B^2 (t1 reduced)
		field.CarryMul(&x2, field.RelaxCast(&z2), &t1)       // x2 = AA*BB
		field.Sub(&t2, &z2, field.UnsafeTightenCast(&t1))    // E = AA-BB (safe, t1 is reduced)

		field.CarryMulSmol(field.UnsafeTightenCast(&t1), &t2, -edwardsD) // E*-d = a24*E (t1 reduced)
		field.Add(&t1, field.UnsafeTightenCast(&t1), &z2)                // AA + a24*E (safe, t1 is reduced)
		field.CarryMul(&z2, &t2, &t1)                                    // z2 = E(AA+a24*E)
	}

	// Finish
	field.CondSwap(&x2, &x3, swap)
	field.CondSwap(&z2, &x3, swap)
	field.CarryInv(&z2, field.RelaxCast(&z2))
	field.CarryMul(&x1, field.RelaxCast(&x2), field.RelaxCast(&z2))
	field.ToBytes(out, &x1)
}

func ScalarBaseMult(out, scalar *[56]byte) {
	ScalarMult(out, scalar, &basePoint)
}
