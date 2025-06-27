// The MIT License (MIT)
//
// Copyright (c) 2014-2015 Cryptography Research, Inc.
// Copyright (c) 2015-2021 Yawning Angel
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

//go:build (386 || arm || mips || mipsle || wasm || mips64le || mips64 || riscv64 || loong64 || force32bit) && !force64bit

package field

// This started out as a straight forward Go port of Michael Hamburg's 32-bit
// x448 code, with some minor changes to make it more idiomatic, but has since
// been altered to be approximately API-compatible with fiat-crypto's 64-bit
// p448solinas.
//
// WARNING:
//  * fiat-crypto is unconditionally alias-safe.  Arguments in this package
//    must alias exactly or not at all.
//  * Until someone does the range analysis to show that CarryMul can actually
//    handle non-reduced arguments, this side-steps the issue by doing a weak
//    reduction after each Add/Sub operation (so LooseFieldElement outputs are
//    actually TightFieldElements).

const (
	wBits     = 32
	lBits     = (wBits * 7 / 8)
	x448Limbs = (448 / lBits)
	lMask     = (1 << lBits) - 1
)

type LimbUint uint32

func (n LimbUint) unwrap() uint32 {
	return uint32(n)
}

type (
	LooseFieldElement [x448Limbs]uint32
	TightFieldElement [x448Limbs]uint32
)

var p = TightFieldElement{
	lMask, lMask, lMask, lMask, lMask, lMask, lMask, lMask,
	lMask - 1, lMask, lMask, lMask, lMask, lMask, lMask, lMask,
}

func CarryMul(out1 *TightFieldElement, arg1 *LooseFieldElement, arg2 *LooseFieldElement) {
	var aa LooseFieldElement
	copy(aa[:], arg1[:])

	// XXX/yawning: This was a massive gain on amd64, but now that there
	// is a dedicated 64-bit backend, it is probably worth revisiting to
	// see if using an array is better on 32-bit targets due to register
	// pressure.
	var accum0, accum1, accum2, accum3, accum4, accum5, accum6, accum7, accum8, accum9, accum10, accum11, accum12, accum13, accum14, accum15 uint64

	bv := (uint64)(arg2[0])
	accum0 += bv * (uint64)(aa[0])
	accum1 += bv * (uint64)(aa[1])
	accum2 += bv * (uint64)(aa[2])
	accum3 += bv * (uint64)(aa[3])
	accum4 += bv * (uint64)(aa[4])
	accum5 += bv * (uint64)(aa[5])
	accum6 += bv * (uint64)(aa[6])
	accum7 += bv * (uint64)(aa[7])
	accum8 += bv * (uint64)(aa[8])
	accum9 += bv * (uint64)(aa[9])
	accum10 += bv * (uint64)(aa[10])
	accum11 += bv * (uint64)(aa[11])
	accum12 += bv * (uint64)(aa[12])
	accum13 += bv * (uint64)(aa[13])
	accum14 += bv * (uint64)(aa[14])
	accum15 += bv * (uint64)(aa[15])
	aa[(x448Limbs-1-0)^(x448Limbs/2)] += aa[x448Limbs-1-0]

	bv = (uint64)(arg2[1])
	accum1 += bv * (uint64)(aa[0])
	accum2 += bv * (uint64)(aa[1])
	accum3 += bv * (uint64)(aa[2])
	accum4 += bv * (uint64)(aa[3])
	accum5 += bv * (uint64)(aa[4])
	accum6 += bv * (uint64)(aa[5])
	accum7 += bv * (uint64)(aa[6])
	accum8 += bv * (uint64)(aa[7])
	accum9 += bv * (uint64)(aa[8])
	accum10 += bv * (uint64)(aa[9])
	accum11 += bv * (uint64)(aa[10])
	accum12 += bv * (uint64)(aa[11])
	accum13 += bv * (uint64)(aa[12])
	accum14 += bv * (uint64)(aa[13])
	accum15 += bv * (uint64)(aa[14])
	accum0 += bv * (uint64)(aa[15])
	aa[(x448Limbs-1-1)^(x448Limbs/2)] += aa[x448Limbs-1-1]

	bv = (uint64)(arg2[2])
	accum2 += bv * (uint64)(aa[0])
	accum3 += bv * (uint64)(aa[1])
	accum4 += bv * (uint64)(aa[2])
	accum5 += bv * (uint64)(aa[3])
	accum6 += bv * (uint64)(aa[4])
	accum7 += bv * (uint64)(aa[5])
	accum8 += bv * (uint64)(aa[6])
	accum9 += bv * (uint64)(aa[7])
	accum10 += bv * (uint64)(aa[8])
	accum11 += bv * (uint64)(aa[9])
	accum12 += bv * (uint64)(aa[10])
	accum13 += bv * (uint64)(aa[11])
	accum14 += bv * (uint64)(aa[12])
	accum15 += bv * (uint64)(aa[13])
	accum0 += bv * (uint64)(aa[14])
	accum1 += bv * (uint64)(aa[15])
	aa[(x448Limbs-1-2)^(x448Limbs/2)] += aa[x448Limbs-1-2]

	bv = (uint64)(arg2[3])
	accum3 += bv * (uint64)(aa[0])
	accum4 += bv * (uint64)(aa[1])
	accum5 += bv * (uint64)(aa[2])
	accum6 += bv * (uint64)(aa[3])
	accum7 += bv * (uint64)(aa[4])
	accum8 += bv * (uint64)(aa[5])
	accum9 += bv * (uint64)(aa[6])
	accum10 += bv * (uint64)(aa[7])
	accum11 += bv * (uint64)(aa[8])
	accum12 += bv * (uint64)(aa[9])
	accum13 += bv * (uint64)(aa[10])
	accum14 += bv * (uint64)(aa[11])
	accum15 += bv * (uint64)(aa[12])
	accum0 += bv * (uint64)(aa[13])
	accum1 += bv * (uint64)(aa[14])
	accum2 += bv * (uint64)(aa[15])
	aa[(x448Limbs-1-3)^(x448Limbs/2)] += aa[x448Limbs-1-3]

	bv = (uint64)(arg2[4])
	accum4 += bv * (uint64)(aa[0])
	accum5 += bv * (uint64)(aa[1])
	accum6 += bv * (uint64)(aa[2])
	accum7 += bv * (uint64)(aa[3])
	accum8 += bv * (uint64)(aa[4])
	accum9 += bv * (uint64)(aa[5])
	accum10 += bv * (uint64)(aa[6])
	accum11 += bv * (uint64)(aa[7])
	accum12 += bv * (uint64)(aa[8])
	accum13 += bv * (uint64)(aa[9])
	accum14 += bv * (uint64)(aa[10])
	accum15 += bv * (uint64)(aa[11])
	accum0 += bv * (uint64)(aa[12])
	accum1 += bv * (uint64)(aa[13])
	accum2 += bv * (uint64)(aa[14])
	accum3 += bv * (uint64)(aa[15])
	aa[(x448Limbs-1-4)^(x448Limbs/2)] += aa[x448Limbs-1-4]

	bv = (uint64)(arg2[5])
	accum5 += bv * (uint64)(aa[0])
	accum6 += bv * (uint64)(aa[1])
	accum7 += bv * (uint64)(aa[2])
	accum8 += bv * (uint64)(aa[3])
	accum9 += bv * (uint64)(aa[4])
	accum10 += bv * (uint64)(aa[5])
	accum11 += bv * (uint64)(aa[6])
	accum12 += bv * (uint64)(aa[7])
	accum13 += bv * (uint64)(aa[8])
	accum14 += bv * (uint64)(aa[9])
	accum15 += bv * (uint64)(aa[10])
	accum0 += bv * (uint64)(aa[11])
	accum1 += bv * (uint64)(aa[12])
	accum2 += bv * (uint64)(aa[13])
	accum3 += bv * (uint64)(aa[14])
	accum4 += bv * (uint64)(aa[15])
	aa[(x448Limbs-1-5)^(x448Limbs/2)] += aa[x448Limbs-1-5]

	bv = (uint64)(arg2[6])
	accum6 += bv * (uint64)(aa[0])
	accum7 += bv * (uint64)(aa[1])
	accum8 += bv * (uint64)(aa[2])
	accum9 += bv * (uint64)(aa[3])
	accum10 += bv * (uint64)(aa[4])
	accum11 += bv * (uint64)(aa[5])
	accum12 += bv * (uint64)(aa[6])
	accum13 += bv * (uint64)(aa[7])
	accum14 += bv * (uint64)(aa[8])
	accum15 += bv * (uint64)(aa[9])
	accum0 += bv * (uint64)(aa[10])
	accum1 += bv * (uint64)(aa[11])
	accum2 += bv * (uint64)(aa[12])
	accum3 += bv * (uint64)(aa[13])
	accum4 += bv * (uint64)(aa[14])
	accum5 += bv * (uint64)(aa[15])
	aa[(x448Limbs-1-6)^(x448Limbs/2)] += aa[x448Limbs-1-6]

	bv = (uint64)(arg2[7])
	accum7 += bv * (uint64)(aa[0])
	accum8 += bv * (uint64)(aa[1])
	accum9 += bv * (uint64)(aa[2])
	accum10 += bv * (uint64)(aa[3])
	accum11 += bv * (uint64)(aa[4])
	accum12 += bv * (uint64)(aa[5])
	accum13 += bv * (uint64)(aa[6])
	accum14 += bv * (uint64)(aa[7])
	accum15 += bv * (uint64)(aa[8])
	accum0 += bv * (uint64)(aa[9])
	accum1 += bv * (uint64)(aa[10])
	accum2 += bv * (uint64)(aa[11])
	accum3 += bv * (uint64)(aa[12])
	accum4 += bv * (uint64)(aa[13])
	accum5 += bv * (uint64)(aa[14])
	accum6 += bv * (uint64)(aa[15])
	aa[(x448Limbs-1-7)^(x448Limbs/2)] += aa[x448Limbs-1-7]

	bv = (uint64)(arg2[8])
	accum8 += bv * (uint64)(aa[0])
	accum9 += bv * (uint64)(aa[1])
	accum10 += bv * (uint64)(aa[2])
	accum11 += bv * (uint64)(aa[3])
	accum12 += bv * (uint64)(aa[4])
	accum13 += bv * (uint64)(aa[5])
	accum14 += bv * (uint64)(aa[6])
	accum15 += bv * (uint64)(aa[7])
	accum0 += bv * (uint64)(aa[8])
	accum1 += bv * (uint64)(aa[9])
	accum2 += bv * (uint64)(aa[10])
	accum3 += bv * (uint64)(aa[11])
	accum4 += bv * (uint64)(aa[12])
	accum5 += bv * (uint64)(aa[13])
	accum6 += bv * (uint64)(aa[14])
	accum7 += bv * (uint64)(aa[15])
	aa[(x448Limbs-1-8)^(x448Limbs/2)] += aa[x448Limbs-1-8]

	bv = (uint64)(arg2[9])
	accum9 += bv * (uint64)(aa[0])
	accum10 += bv * (uint64)(aa[1])
	accum11 += bv * (uint64)(aa[2])
	accum12 += bv * (uint64)(aa[3])
	accum13 += bv * (uint64)(aa[4])
	accum14 += bv * (uint64)(aa[5])
	accum15 += bv * (uint64)(aa[6])
	accum0 += bv * (uint64)(aa[7])
	accum1 += bv * (uint64)(aa[8])
	accum2 += bv * (uint64)(aa[9])
	accum3 += bv * (uint64)(aa[10])
	accum4 += bv * (uint64)(aa[11])
	accum5 += bv * (uint64)(aa[12])
	accum6 += bv * (uint64)(aa[13])
	accum7 += bv * (uint64)(aa[14])
	accum8 += bv * (uint64)(aa[15])
	aa[(x448Limbs-1-9)^(x448Limbs/2)] += aa[x448Limbs-1-9]

	bv = (uint64)(arg2[10])
	accum10 += bv * (uint64)(aa[0])
	accum11 += bv * (uint64)(aa[1])
	accum12 += bv * (uint64)(aa[2])
	accum13 += bv * (uint64)(aa[3])
	accum14 += bv * (uint64)(aa[4])
	accum15 += bv * (uint64)(aa[5])
	accum0 += bv * (uint64)(aa[6])
	accum1 += bv * (uint64)(aa[7])
	accum2 += bv * (uint64)(aa[8])
	accum3 += bv * (uint64)(aa[9])
	accum4 += bv * (uint64)(aa[10])
	accum5 += bv * (uint64)(aa[11])
	accum6 += bv * (uint64)(aa[12])
	accum7 += bv * (uint64)(aa[13])
	accum8 += bv * (uint64)(aa[14])
	accum9 += bv * (uint64)(aa[15])
	aa[(x448Limbs-1-10)^(x448Limbs/2)] += aa[x448Limbs-1-10]

	bv = (uint64)(arg2[11])
	accum11 += bv * (uint64)(aa[0])
	accum12 += bv * (uint64)(aa[1])
	accum13 += bv * (uint64)(aa[2])
	accum14 += bv * (uint64)(aa[3])
	accum15 += bv * (uint64)(aa[4])
	accum0 += bv * (uint64)(aa[5])
	accum1 += bv * (uint64)(aa[6])
	accum2 += bv * (uint64)(aa[7])
	accum3 += bv * (uint64)(aa[8])
	accum4 += bv * (uint64)(aa[9])
	accum5 += bv * (uint64)(aa[10])
	accum6 += bv * (uint64)(aa[11])
	accum7 += bv * (uint64)(aa[12])
	accum8 += bv * (uint64)(aa[13])
	accum9 += bv * (uint64)(aa[14])
	accum10 += bv * (uint64)(aa[15])
	aa[(x448Limbs-1-11)^(x448Limbs/2)] += aa[x448Limbs-1-11]

	bv = (uint64)(arg2[12])
	accum12 += bv * (uint64)(aa[0])
	accum13 += bv * (uint64)(aa[1])
	accum14 += bv * (uint64)(aa[2])
	accum15 += bv * (uint64)(aa[3])
	accum0 += bv * (uint64)(aa[4])
	accum1 += bv * (uint64)(aa[5])
	accum2 += bv * (uint64)(aa[6])
	accum3 += bv * (uint64)(aa[7])
	accum4 += bv * (uint64)(aa[8])
	accum5 += bv * (uint64)(aa[9])
	accum6 += bv * (uint64)(aa[10])
	accum7 += bv * (uint64)(aa[11])
	accum8 += bv * (uint64)(aa[12])
	accum9 += bv * (uint64)(aa[13])
	accum10 += bv * (uint64)(aa[14])
	accum11 += bv * (uint64)(aa[15])
	aa[(x448Limbs-1-12)^(x448Limbs/2)] += aa[x448Limbs-1-12]

	bv = (uint64)(arg2[13])
	accum13 += bv * (uint64)(aa[0])
	accum14 += bv * (uint64)(aa[1])
	accum15 += bv * (uint64)(aa[2])
	accum0 += bv * (uint64)(aa[3])
	accum1 += bv * (uint64)(aa[4])
	accum2 += bv * (uint64)(aa[5])
	accum3 += bv * (uint64)(aa[6])
	accum4 += bv * (uint64)(aa[7])
	accum5 += bv * (uint64)(aa[8])
	accum6 += bv * (uint64)(aa[9])
	accum7 += bv * (uint64)(aa[10])
	accum8 += bv * (uint64)(aa[11])
	accum9 += bv * (uint64)(aa[12])
	accum10 += bv * (uint64)(aa[13])
	accum11 += bv * (uint64)(aa[14])
	accum12 += bv * (uint64)(aa[15])
	aa[(x448Limbs-1-13)^(x448Limbs/2)] += aa[x448Limbs-1-13]

	bv = (uint64)(arg2[14])
	accum14 += bv * (uint64)(aa[0])
	accum15 += bv * (uint64)(aa[1])
	accum0 += bv * (uint64)(aa[2])
	accum1 += bv * (uint64)(aa[3])
	accum2 += bv * (uint64)(aa[4])
	accum3 += bv * (uint64)(aa[5])
	accum4 += bv * (uint64)(aa[6])
	accum5 += bv * (uint64)(aa[7])
	accum6 += bv * (uint64)(aa[8])
	accum7 += bv * (uint64)(aa[9])
	accum8 += bv * (uint64)(aa[10])
	accum9 += bv * (uint64)(aa[11])
	accum10 += bv * (uint64)(aa[12])
	accum11 += bv * (uint64)(aa[13])
	accum12 += bv * (uint64)(aa[14])
	accum13 += bv * (uint64)(aa[15])
	aa[(x448Limbs-1-14)^(x448Limbs/2)] += aa[x448Limbs-1-14]

	bv = (uint64)(arg2[15])
	accum15 += bv * (uint64)(aa[0])
	accum0 += bv * (uint64)(aa[1])
	accum1 += bv * (uint64)(aa[2])
	accum2 += bv * (uint64)(aa[3])
	accum3 += bv * (uint64)(aa[4])
	accum4 += bv * (uint64)(aa[5])
	accum5 += bv * (uint64)(aa[6])
	accum6 += bv * (uint64)(aa[7])
	accum7 += bv * (uint64)(aa[8])
	accum8 += bv * (uint64)(aa[9])
	accum9 += bv * (uint64)(aa[10])
	accum10 += bv * (uint64)(aa[11])
	accum11 += bv * (uint64)(aa[12])
	accum12 += bv * (uint64)(aa[13])
	accum13 += bv * (uint64)(aa[14])
	accum14 += bv * (uint64)(aa[15])
	aa[(x448Limbs-1-15)^(x448Limbs/2)] += aa[x448Limbs-1-15]

	accum15 += accum14 >> lBits
	accum14 &= lMask
	accum8 += accum15 >> lBits

	accum0 += accum15 >> lBits
	accum15 &= lMask
	accum1 += accum0 >> lBits
	accum0 &= lMask
	accum2 += accum1 >> lBits
	accum1 &= lMask
	accum3 += accum2 >> lBits
	accum2 &= lMask
	accum4 += accum3 >> lBits
	accum3 &= lMask
	accum5 += accum4 >> lBits
	accum4 &= lMask
	accum6 += accum5 >> lBits
	accum5 &= lMask
	accum7 += accum6 >> lBits
	accum6 &= lMask
	accum8 += accum7 >> lBits
	accum7 &= lMask
	accum9 += accum8 >> lBits
	accum8 &= lMask
	accum10 += accum9 >> lBits
	accum9 &= lMask
	accum11 += accum10 >> lBits
	accum10 &= lMask
	accum12 += accum11 >> lBits
	accum11 &= lMask
	accum13 += accum12 >> lBits
	accum12 &= lMask
	accum14 += accum13 >> lBits
	accum13 &= lMask
	accum15 += accum14 >> lBits
	accum14 &= lMask

	out1[0] = (uint32)(accum0)
	out1[1] = (uint32)(accum1)
	out1[2] = (uint32)(accum2)
	out1[3] = (uint32)(accum3)
	out1[4] = (uint32)(accum4)
	out1[5] = (uint32)(accum5)
	out1[6] = (uint32)(accum6)
	out1[7] = (uint32)(accum7)
	out1[8] = (uint32)(accum8)
	out1[9] = (uint32)(accum9)
	out1[10] = (uint32)(accum10)
	out1[11] = (uint32)(accum11)
	out1[12] = (uint32)(accum12)
	out1[13] = (uint32)(accum13)
	out1[14] = (uint32)(accum14)
	out1[15] = (uint32)(accum15)
}

func CarrySquare(out1 *TightFieldElement, arg1 *LooseFieldElement) {
	CarryMul(out1, arg1, arg1)
}

func Add(out1 *LooseFieldElement, arg1 *TightFieldElement, arg2 *TightFieldElement) {
	out1[0] = arg1[0] + arg2[0]
	out1[1] = arg1[1] + arg2[1]
	out1[2] = arg1[2] + arg2[2]
	out1[3] = arg1[3] + arg2[3]
	out1[4] = arg1[4] + arg2[4]
	out1[5] = arg1[5] + arg2[5]
	out1[6] = arg1[6] + arg2[6]
	out1[7] = arg1[7] + arg2[7]
	out1[8] = arg1[8] + arg2[8]
	out1[9] = arg1[9] + arg2[9]
	out1[10] = arg1[10] + arg2[10]
	out1[11] = arg1[11] + arg2[11]
	out1[12] = arg1[12] + arg2[12]
	out1[13] = arg1[13] + arg2[13]
	out1[14] = arg1[14] + arg2[14]
	out1[15] = arg1[15] + arg2[15]

	weakReduce(out1)
}

func Sub(out1 *LooseFieldElement, arg1 *TightFieldElement, arg2 *TightFieldElement) {
	out1[0] = arg1[0] - arg2[0] + 2*lMask
	out1[1] = arg1[1] - arg2[1] + 2*lMask
	out1[2] = arg1[2] - arg2[2] + 2*lMask
	out1[3] = arg1[3] - arg2[3] + 2*lMask
	out1[4] = arg1[4] - arg2[4] + 2*lMask
	out1[5] = arg1[5] - arg2[5] + 2*lMask
	out1[6] = arg1[6] - arg2[6] + 2*lMask
	out1[7] = arg1[7] - arg2[7] + 2*lMask
	out1[8] = arg1[8] - arg2[8] + 2*(lMask-1)
	out1[9] = arg1[9] - arg2[9] + 2*lMask
	out1[10] = arg1[10] - arg2[10] + 2*lMask
	out1[11] = arg1[11] - arg2[11] + 2*lMask
	out1[12] = arg1[12] - arg2[12] + 2*lMask
	out1[13] = arg1[13] - arg2[13] + 2*lMask
	out1[14] = arg1[14] - arg2[14] + 2*lMask
	out1[15] = arg1[15] - arg2[15] + 2*lMask

	weakReduce(out1)
}

func ToBytes(out1 *[56]uint8, arg1 *TightFieldElement) {
	var a TightFieldElement
	canon(&a, RelaxCast(arg1))

	var (
		k    int
		bits uint
		buf  uint64
	)
	for i, v := range a {
		buf |= (uint64)(v) << bits
		for bits += lBits; (bits >= 8 || i == x448Limbs-1) && k < 56; bits, buf = bits-8, buf>>8 {
			out1[k] = (byte)(buf)
			k++
		}
	}
}

func FromBytes(out1 *TightFieldElement, arg1 *[56]uint8) {
	var (
		k    int
		bits uint
		buf  uint64
	)

	for i, v := range arg1 {
		buf |= (uint64)(v) << bits
		for bits += 8; (bits >= lBits || i == 56-1) && k < x448Limbs; bits, buf = bits-lBits, buf>>lBits {
			out1[k] = (uint32)(buf & lMask)
			k++
		}
	}
}

func weakReduce(x *LooseFieldElement) {
	// TODO/yawning: Maybe change this to provide Carry.
	x[x448Limbs/2] += x[x448Limbs-1] >> lBits

	x[0] += x[15] >> lBits
	x[15] &= lMask
	x[1] += x[0] >> lBits
	x[0] &= lMask
	x[2] += x[1] >> lBits
	x[1] &= lMask
	x[3] += x[2] >> lBits
	x[2] &= lMask
	x[4] += x[3] >> lBits
	x[3] &= lMask
	x[5] += x[4] >> lBits
	x[4] &= lMask
	x[6] += x[5] >> lBits
	x[5] &= lMask
	x[7] += x[6] >> lBits
	x[6] &= lMask
	x[8] += x[7] >> lBits
	x[7] &= lMask
	x[9] += x[8] >> lBits
	x[8] &= lMask
	x[10] += x[9] >> lBits
	x[9] &= lMask
	x[11] += x[10] >> lBits
	x[10] &= lMask
	x[12] += x[11] >> lBits
	x[11] &= lMask
	x[13] += x[12] >> lBits
	x[12] &= lMask
	x[14] += x[13] >> lBits
	x[13] &= lMask
	x[15] += x[14] >> lBits
	x[14] &= lMask
}

func canon(out1 *TightFieldElement, arg1 *LooseFieldElement) {
	var a LooseFieldElement
	copy(a[:], arg1[:])
	weakReduce(&a)

	// Subtract p with borrow.
	var carry int64
	for i, v := range a {
		carry = carry + (int64)(v) - (int64)(p[i])
		a[i] = (uint32)(carry & lMask)
		carry >>= lBits
	}

	addback := carry
	carry = 0

	// Add it back.
	for i, v := range a {
		carry = carry + (int64)(v) + (int64)(p[i]&(uint32)(addback))
		out1[i] = uint32(carry & lMask)
		carry >>= lBits
	}
}
