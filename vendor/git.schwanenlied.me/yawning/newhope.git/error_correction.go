// error_correction.go - NewHope key exchange error correction.
//
// To the extent possible under law, Yawning Angel has waived all copyright
// and related or neighboring rights to newhope, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package newhope

import "git.schwanenlied.me/yawning/chacha20.git"

func abs(v int32) int32 {
	mask := v >> 31
	return (v ^ mask) - mask
}

func f(v0, v1 *int32, x int32) int32 {
	// The`ref` code uses uint32 for x, but none of the values ever get large
	// enough for that, and that would be cast-tastic due to Go being Go.

	// Next 6 lines compute t = x/PARAM_Q
	b := x * 2730
	t := b >> 25
	b = x - t*paramQ
	b = (paramQ - 1) - b
	b >>= 31
	t -= b

	r := t & 1
	xit := t >> 1
	*v0 = xit + r // v0 = round(x/(2*PARAM_Q))

	t--
	r = t & 1
	*v1 = (t >> 1) + r

	return abs(x - ((*v0) * 2 * paramQ))
}

func g(x int32) int32 {
	// Next 6 lines compute t = x/(4 *PARAMQ)
	b := x * 2730
	t := b >> 27
	b = x - t*(paramQ*4)
	b = (paramQ * 4) - b
	b >>= 31
	t -= b

	c := t & 1
	t = (t >> 1) + c // t = round(x/(8*PARAM_Q))

	t *= 8 * paramQ

	return abs(t - x)
}

func llDecode(xi0, xi1, xi2, xi3 int32) int16 {
	t := g(xi0)
	t += g(xi1)
	t += g(xi2)
	t += g(xi3)

	t -= 8 * paramQ
	t >>= 31
	return int16(t & 1)
}

func (c *poly) helpRec(v *poly, seed *[SeedBytes]byte, nonce byte) {
	var v0, v1, vTmp [4]int32
	var k int32
	var rand [32]byte
	var n [8]byte

	n[7] = nonce

	stream, err := chacha20.NewCipher(seed[:], n[:])
	if err != nil {
		panic(err)
	}
	stream.KeyStream(rand[:])
	stream.Reset()
	defer memwipe(rand[:])

	for i := uint(0); i < 256; i++ {
		rBit := int32((rand[i>>3] >> (i & 7)) & 1)

		vTmp[0], vTmp[1], vTmp[2], vTmp[3] = int32(v.coeffs[i]), int32(v.coeffs[256+i]), int32(v.coeffs[512+i]), int32(v.coeffs[768+i])

		// newhope-20151209 - New version of the reconciliation.
		k = f(&v0[0], &v1[0], 8*vTmp[0]+4*rBit)
		k += f(&v0[1], &v1[1], 8*vTmp[1]+4*rBit)
		k += f(&v0[2], &v1[2], 8*vTmp[2]+4*rBit)
		k += f(&v0[3], &v1[3], 8*vTmp[3]+4*rBit)

		k = (2*paramQ - 1 - k) >> 31

		vTmp[0] = ((^k) & v0[0]) ^ (k & v1[0])
		vTmp[1] = ((^k) & v0[1]) ^ (k & v1[1])
		vTmp[2] = ((^k) & v0[2]) ^ (k & v1[2])
		vTmp[3] = ((^k) & v0[3]) ^ (k & v1[3])

		c.coeffs[0+i] = uint16((vTmp[0] - vTmp[3]) & 3)
		c.coeffs[256+i] = uint16((vTmp[1] - vTmp[3]) & 3)
		c.coeffs[512+i] = uint16((vTmp[2] - vTmp[3]) & 3)
		c.coeffs[768+i] = uint16((-k + 2*vTmp[3]) & 3)
	}

	for i := range vTmp {
		vTmp[i] = 0
	}
}

func rec(key *[32]byte, v, c *poly) {
	var tmp, vTmp, cTmp [4]int32
	for i := range key {
		key[i] = 0
	}

	for i := uint(0); i < 256; i++ {
		vTmp[0], vTmp[1], vTmp[2], vTmp[3] = int32(v.coeffs[i]), int32(v.coeffs[256+i]), int32(v.coeffs[512+i]), int32(v.coeffs[768+i])
		cTmp[0], cTmp[1], cTmp[2], cTmp[3] = int32(c.coeffs[i]), int32(c.coeffs[256+i]), int32(c.coeffs[512+i]), int32(c.coeffs[768+i])
		tmp[0] = 16*paramQ + 8*vTmp[0] - paramQ*(2*cTmp[0]+cTmp[3])
		tmp[1] = 16*paramQ + 8*vTmp[1] - paramQ*(2*cTmp[1]+cTmp[3])
		tmp[2] = 16*paramQ + 8*vTmp[2] - paramQ*(2*cTmp[2]+cTmp[3])
		tmp[3] = 16*paramQ + 8*vTmp[3] - paramQ*(cTmp[3])

		key[i>>3] |= byte(llDecode(tmp[0], tmp[1], tmp[2], tmp[3]) << (i & 7))
	}

	for i := 0; i < 4; i++ {
		tmp[i] = 0
		vTmp[i] = 0
		cTmp[i] = 0
	}
}
