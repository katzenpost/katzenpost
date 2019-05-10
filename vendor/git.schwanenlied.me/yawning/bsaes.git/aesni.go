// Copyright (c) 2017 Yawning Angel <yawning at schwanenlied dot me>
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
// BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
// ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// +build go1.6
// +build !gccgo
// +build !appengine
// +build !noasm
// +build amd64

package bsaes

//go:noescape
func cpuidAMD64(cpuidParams *uint32)

func isCryptoAESSafe() bool {
	return supportsAESNI()
}

func supportsAESNI() bool {
	const (
		pclmulBit = 1 << 1
		aesniBit  = 1 << 25
	)

	// Check for AES-NI and PCLMUL support.
	// CPUID.(EAX=01H, ECX=0H):ECX.AESNI[bit 25]==1
	//                         ECX.PCLMUL[bit 1]==1
	regs := [4]uint32{0x01}
	cpuidAMD64(&regs[0])

	return regs[2]&pclmulBit != 0 && regs[2]&aesniBit != 0
}
