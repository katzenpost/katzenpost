// The MIT License (MIT)
//
// Copyright (c) 2014-2015 Cryptography Research, Inc.
// Copyright (c) 2015-2021 Yawning Angel.
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

package field

func Set(out1, arg1 *TightFieldElement) {
	// Note: Not alias-safe, if out1/arg1 do not exactly overlap.
	for i := range arg1 {
		out1[i] = arg1[i]
	}
}

func RelaxCast(arg1 *TightFieldElement) *LooseFieldElement {
	return (*LooseFieldElement)(arg1)
}

func UnsafeTightenCast(arg1 *LooseFieldElement) *TightFieldElement {
	return (*TightFieldElement)(arg1)
}

func CondSwap(arg1, arg2 *TightFieldElement, swap LimbUint) {
	swapTyped := swap.unwrap()

	// Note: Not alias-safe, if arg1/arg2 do not exactly overlap.
	for i := range arg1 {
		s := (arg1[i] ^ arg2[i]) & swapTyped
		arg1[i] ^= s
		arg2[i] ^= s
	}
}

func CarryMulSmol(out1 *TightFieldElement, arg1 *LooseFieldElement, smol LimbUint) {
	// XXX/yawning: fiat provides a special-case routine for `-D` for
	// curve25519, but not curve2448 (PERF).
	arg2 := LooseFieldElement{smol.unwrap()}
	CarryMul(out1, arg1, &arg2)
}

func CarryInv(out1 *TightFieldElement, arg1 *LooseFieldElement) {
	var z, w TightFieldElement

	CarrySquare(&z, arg1)               // x^2
	carryInvSqrt(&w, RelaxCast(&z))     // +- 1/sqrt(x^2) = +- 1/x
	CarrySquare(&z, RelaxCast(&w))      // 1/x^2
	CarryMul(out1, arg1, RelaxCast(&z)) // 1/x
}

func carryPow2k(out1 *TightFieldElement, arg1 *LooseFieldElement, k uint) {
	// XXX/yawning: fiat should provide something like this, because
	// shuffling data in/out of registers adds up (PERF).

	if k == 0 {
		panic("internal/field: k must be greater than 0")
	}

	CarrySquare(out1, arg1)
	for i := uint(1); i < k; i++ {
		CarrySquare(out1, RelaxCast(out1))
	}
}

func carryInvSqrt(out1 *TightFieldElement, arg1 *LooseFieldElement) {
	var a, b, c TightFieldElement

	CarrySquare(&c, arg1)

	CarryMul(&b, arg1, RelaxCast(&c))
	CarrySquare(&c, RelaxCast(&b))

	CarryMul(&b, arg1, RelaxCast(&c))
	carryPow2k(&c, RelaxCast(&b), 3)

	CarryMul(&a, RelaxCast(&b), RelaxCast(&c))
	carryPow2k(&c, RelaxCast(&a), 3)

	CarryMul(&a, RelaxCast(&b), RelaxCast(&c))
	carryPow2k(&c, RelaxCast(&a), 9)

	CarryMul(&b, RelaxCast(&a), RelaxCast(&c))
	CarrySquare(&c, RelaxCast(&b))

	CarryMul(&a, arg1, RelaxCast(&c))
	carryPow2k(&c, RelaxCast(&a), 18)

	CarryMul(&a, RelaxCast(&b), RelaxCast(&c))
	carryPow2k(&c, RelaxCast(&a), 37)

	CarryMul(&b, RelaxCast(&a), RelaxCast(&c))
	carryPow2k(&c, RelaxCast(&b), 37)

	CarryMul(&b, RelaxCast(&a), RelaxCast(&c))
	carryPow2k(&c, RelaxCast(&b), 111)

	CarryMul(&a, RelaxCast(&b), RelaxCast(&c))
	CarrySquare(&c, RelaxCast(&a))

	CarryMul(&b, arg1, RelaxCast(&c))
	carryPow2k(&c, RelaxCast(&b), 223)

	CarryMul(out1, RelaxCast(&a), RelaxCast(&c))
}
