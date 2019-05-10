// poly_simple.go - NewHope-Simple polynomial.
//
// To the extent possible under law, Yawning Angel has waived all copyright
// and related or neighboring rights to newhope, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package newhope

func coeffFreeze(x uint16) uint16 {
	var c int16

	r := barrettReduce(x)
	m := r - paramQ
	c = int16(m)
	c >>= 15
	r = m ^ ((r ^ m) & uint16(c))

	return r
}

// Computes abs(x-Q/2)
func flipAbs(x uint16) uint16 {
	r := int16(coeffFreeze(x))
	r = r - paramQ/2
	m := r >> 15
	return uint16((r + m) ^ m)
}

func (p *poly) compress(r []byte) {
	var t [8]uint32

	for i, k := 0, 0; i < paramN; i, k = i+8, k+3 {
		for j := range t {
			t[j] = uint32(coeffFreeze(p.coeffs[i+j]))
			t[j] = (((t[j] << 3) + paramQ/2) / paramQ) & 0x7
		}

		r[k] = byte(t[0]) | byte(t[1]<<3) | byte(t[2]<<6)
		r[k+1] = byte(t[2]>>2) | byte(t[3]<<1) | byte(t[4]<<4) | byte(t[5]<<7)
		r[k+2] = byte(t[5]>>1) | byte(t[6]<<2) | byte(t[7]<<5)
	}

	for i := range t {
		t[i] = 0
	}
}

func (p *poly) decompress(a []byte) {
	for i := 0; i < paramN; i += 8 {
		a0, a1, a2 := uint16(a[0]), uint16(a[1]), uint16(a[2])
		p.coeffs[i+0] = a0 & 7
		p.coeffs[i+1] = (a0 >> 3) & 7
		p.coeffs[i+2] = (a0 >> 6) | ((a1 << 2) & 4)
		p.coeffs[i+3] = (a1 >> 1) & 7
		p.coeffs[i+4] = (a1 >> 4) & 7
		p.coeffs[i+5] = (a1 >> 7) | ((a2 << 1) & 6)
		p.coeffs[i+6] = (a2 >> 2) & 7
		p.coeffs[i+7] = (a2 >> 5)
		a = a[3:]
		for j := 0; j < 8; j++ {
			p.coeffs[i+j] = uint16((uint32(p.coeffs[i+j])*paramQ + 4) >> 3)
		}
	}
}

func (p *poly) fromMsg(msg []byte) {
	for i := uint(0); i < 32; i++ { // XXX: const for 32
		for j := uint(0); j < 8; j++ {
			mask := -(uint16((msg[i] >> j) & 1))
			p.coeffs[8*i+j+0] = mask & (paramQ / 2)
			p.coeffs[8*i+j+256] = mask & (paramQ / 2)
			p.coeffs[8*i+j+512] = mask & (paramQ / 2)
			p.coeffs[8*i+j+768] = mask & (paramQ / 2)
		}
	}
}

func (p *poly) toMsg(msg []byte) {
	memwipe(msg[0:32])

	for i := uint(0); i < 256; i++ {
		t := flipAbs(p.coeffs[i+0])
		t += flipAbs(p.coeffs[i+256])
		t += flipAbs(p.coeffs[i+512])
		t += flipAbs(p.coeffs[i+768])

		//t = (~(t - PARAM_Q));
		t = (t - paramQ)
		t >>= 15
		msg[i>>3] |= byte(t << (i & 7))
	}
}

func (p *poly) sub(a, b *poly) {
	for i := range p.coeffs {
		p.coeffs[i] = barrettReduce(a.coeffs[i] + 3*paramQ - b.coeffs[i])
	}
}
