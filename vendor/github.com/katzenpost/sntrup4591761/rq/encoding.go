// Copyright (c) 2017 Company 0 LLC. All rights reserved.
// Use of this source code is governed by an ISC-style
// license that can be found in the LICENSE file.

// These routines are a port of the public domain, C reference implementation.

package rq

import (
	"github.com/katzenpost/sntrup4591761/rq/modq"
)

// Encode packs an element of Rq into 1218 bytes.
func Encode(f *[761]int16) *[1218]byte {
	var f0 int32
	var f1 int32
	var f2 int32
	var f3 int32
	var f4 int32

	const qshift = int32(2295)

	c := new([1218]byte)

	for i, j, k := 0, 0, 0; i < 152; i++ {
		f0 = (int32(f[j+0]) + qshift) * 1
		f1 = (int32(f[j+1]) + qshift) * 3
		f2 = (int32(f[j+2]) + qshift) * 9
		f3 = (int32(f[j+3]) + qshift) * 27
		f4 = (int32(f[j+4]) + qshift) * 81

		j += 5
		f0 += f1 << 11
		c[k+0] = byte(f0)
		f0 >>= 8
		c[k+1] = byte(f0)
		f0 >>= 8
		f0 += f2 << 6
		c[k+2] = byte(f0)
		f0 >>= 8
		c[k+3] = byte(f0)
		f0 >>= 8
		f0 += f3 << 1
		c[k+4] = byte(f0)
		f0 >>= 8
		f0 += f4 << 4
		c[k+5] = byte(f0)
		f0 >>= 8
		c[k+6] = byte(f0)
		f0 >>= 8
		c[k+7] = byte(f0)
		k += 8
	}

	f0 = int32(f[760]) + qshift
	c[1216] = byte(f0)
	c[1217] = byte(f0 >> 8)

	return c
}

// Decode unpacks an element of Rq packed by Encode.
func Decode(c []byte) *[761]int16 {
	var c0 uint32
	var c1 uint32
	var c2 uint32
	var c3 uint32
	var c4 uint32
	var c5 uint32
	var c6 uint32
	var c7 uint32

	var f0 uint32
	var f1 uint32
	var f2 uint32
	var f3 uint32
	var f4 uint32

	const qshift = uint32(2295)
	const q = uint32(4591)

	f := new([761]int16)

	for i, j, k := 0, 0, 0; i < 152; i++ {
		c0 = uint32(c[j+0])
		c1 = uint32(c[j+1])
		c2 = uint32(c[j+2])
		c3 = uint32(c[j+3])
		c4 = uint32(c[j+4])
		c5 = uint32(c[j+5])
		c6 = uint32(c[j+6])
		c7 = uint32(c[j+7])

		j += 8
		c6 += c7 << 8
		f4 = (103564*c6 + 405*(c5+1)) >> 19
		c5 += c6 << 8
		c5 -= (f4 * 81) << 4
		c4 += c5 << 8
		f3 = (9709 * (c4 + 2)) >> 19
		c4 -= (f3 * 27) << 1
		c3 += c4 << 8
		f2 = (233017*c3 + 910*(c2+2)) >> 19
		c2 += c3 << 8
		c2 -= (f2 * 9) << 6
		c1 += c2 << 8
		f1 = (21845*(c1+2) + 85*c0) >> 19
		c1 -= (f1 * 3) << 3
		c0 += c1 << 8
		f0 = c0

		f[k+0] = modq.Freeze(int32(f0 + q - qshift))
		f[k+1] = modq.Freeze(int32(f1 + q - qshift))
		f[k+2] = modq.Freeze(int32(f2 + q - qshift))
		f[k+3] = modq.Freeze(int32(f3 + q - qshift))
		f[k+4] = modq.Freeze(int32(f4 + q - qshift))
		k += 5
	}

	c0 = uint32(c[1216])
	c1 = uint32(c[1217])
	c0 += c1 << 8

	f[760] = modq.Freeze(int32(c0 + q - qshift))

	return f
}

// EncodeRounded packs an element of Rq rounded by Round3 into 1015 bytes.
func EncodeRounded(f *[761]int16) *[1015]byte {
	var f0 int32
	var f1 int32
	var f2 int32

	const qshift = int32(2295)

	c := new([1015]byte)

	for i, j, k := 0, 0, 0; i < 253; i++ {
		f0 = int32(f[j+0]) + qshift
		f1 = int32(f[j+1]) + qshift
		f2 = int32(f[j+2]) + qshift
		j += 3

		f0 = (21846 * f0) >> 16
		f1 = (21846 * f1) >> 16
		f2 = (21846 * f2) >> 16
		f2 *= 3
		f1 += f2 << 9
		f1 *= 3
		f0 += f1 << 9

		c[k+0] = byte(f0)
		f0 >>= 8
		c[k+1] = byte(f0)
		f0 >>= 8
		c[k+2] = byte(f0)
		f0 >>= 8
		c[k+3] = byte(f0)
		k += 4
	}

	f0 = int32(f[759]) + qshift
	f1 = int32(f[760]) + qshift
	f0 = (21846 * f0) >> 16
	f1 = (21846 * f1) >> 16
	f1 *= 3
	f0 += f1 << 9

	c[1012] = byte(f0)
	f0 >>= 8
	c[1013] = byte(f0)
	f0 >>= 8
	c[1014] = byte(f0)

	return c
}

// DecodeRounded unpacks an element of Rq packed by EncodeRounded.
func DecodeRounded(c []byte) *[761]int16 {
	var c0 uint32
	var c1 uint32
	var c2 uint32
	var c3 uint32

	var f0 uint32
	var f1 uint32
	var f2 uint32

	const q = uint32(4591)
	const qshift = uint32(2295)

	f := new([761]int16)

	for i, j, k := 0, 0, 0; i < 253; i++ {
		c0 = uint32(c[j+0])
		c1 = uint32(c[j+1])
		c2 = uint32(c[j+2])
		c3 = uint32(c[j+3])
		j += 4

		f2 = (14913081*c3 + 58254*c2 + 228*(c1+2)) >> 21
		c2 += c3 << 8
		c2 -= (f2 * 9) << 2
		f1 = (89478485*c2 + 349525*c1 + 1365*(c0+1)) >> 21
		c1 += c2 << 8
		c1 -= (f1 * 3) << 1
		c0 += c1 << 8
		f0 = c0

		f[k+0] = modq.Freeze(int32(f0*3 + q - qshift))
		f[k+1] = modq.Freeze(int32(f1*3 + q - qshift))
		f[k+2] = modq.Freeze(int32(f2*3 + q - qshift))
		k += 3
	}

	c0 = uint32(c[1012])
	c1 = uint32(c[1013])
	c2 = uint32(c[1014])

	f1 = (89478485*c2 + 349525*c1 + 1365*(c0+1)) >> 21
	c1 += c2 << 8
	c1 -= (f1 * 3) << 1
	c0 += c1 << 8
	f0 = c0

	f[759] = modq.Freeze(int32(f0*3 + q - qshift))
	f[760] = modq.Freeze(int32(f1*3 + q - qshift))

	return f
}
