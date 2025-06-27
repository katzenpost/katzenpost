// Copyright (c) 2017 Company 0 LLC. All rights reserved.
// Use of this source code is governed by an ISC-style
// license that can be found in the LICENSE file.

// These routines are a port of the public domain, C reference implementation.

package zx

// Encode packs an element of R into 191 bytes.
func Encode(f *[761]int8) *[191]byte {
	c := new([191]byte)

	for i, j := 0, 0; i < 190; i++ {
		c0 := (f[j+0] + 1)
		c0 += (f[j+1] + 1) << 2
		c0 += (f[j+2] + 1) << 4
		c0 += (f[j+3] + 1) << 6
		c[i] = byte(c0)
		j += 4
	}

	c[190] = byte(f[760] + 1)

	return c
}

// Decode unpacks an element of R packed by Encode.
func Decode(c []byte) *[761]int8 {
	f := new([761]int8)

	for i, j := 0, 0; i < 190; i++ {
		c0 := c[i]
		f[j+0] = int8((c0 & 3)) - 1
		c0 >>= 2
		f[j+1] = int8((c0 & 3)) - 1
		c0 >>= 2
		f[j+2] = int8((c0 & 3)) - 1
		c0 >>= 2
		f[j+3] = int8((c0 & 3)) - 1
		j += 4
	}

	f[760] = int8((c[190] & 3)) - 1

	return f
}
