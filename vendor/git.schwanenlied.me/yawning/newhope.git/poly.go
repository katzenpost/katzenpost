// poly.go - NewHope polynomial.
//
// To the extent possible under law, Yawning Angel has waived all copyright
// and related or neighboring rights to newhope, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package newhope

import (
	"encoding/binary"

	"git.schwanenlied.me/yawning/chacha20.git"
	"golang.org/x/crypto/sha3"
)

const (
	// PolyBytes is the length of an encoded polynomial in bytes.
	PolyBytes = 1792

	shake128Rate = 168 // Stupid that this isn't exposed.
)

type poly struct {
	coeffs [paramN]uint16
}

func (p *poly) reset() {
	for i := range p.coeffs {
		p.coeffs[i] = 0
	}
}

func (p *poly) fromBytes(a []byte) {
	for i := 0; i < paramN/4; i++ {
		p.coeffs[4*i+0] = uint16(a[7*i+0]) | ((uint16(a[7*i+1]) & 0x3f) << 8)
		p.coeffs[4*i+1] = (uint16(a[7*i+1]) >> 6) | (uint16(a[7*i+2]) << 2) | ((uint16(a[7*i+3]) & 0x0f) << 10)

		p.coeffs[4*i+2] = (uint16(a[7*i+3]) >> 4) | (uint16(a[7*i+4]) << 4) | ((uint16(a[7*i+5]) & 0x03) << 12)
		p.coeffs[4*i+3] = (uint16(a[7*i+5]) >> 2) | (uint16(a[7*i+6]) << 6)
	}
}

func (p *poly) toBytes(r []byte) {
	for i := 0; i < paramN/4; i++ {
		// Make sure that coefficients have only 14 bits.
		t0 := barrettReduce(p.coeffs[4*i+0])
		t1 := barrettReduce(p.coeffs[4*i+1])
		t2 := barrettReduce(p.coeffs[4*i+2])
		t3 := barrettReduce(p.coeffs[4*i+3])

		// Make sure that coefficients are in [0,q]
		m := t0 - paramQ
		c := int16(m)
		c >>= 15
		t0 = m ^ ((t0 ^ m) & uint16(c))

		m = t1 - paramQ
		c = int16(m)
		c >>= 15
		t1 = m ^ ((t1 ^ m) & uint16(c))

		m = t2 - paramQ
		c = int16(m)
		c >>= 15
		t2 = m ^ ((t2 ^ m) & uint16(c))

		m = t3 - paramQ
		c = int16(m)
		c >>= 15
		t3 = m ^ ((t3 ^ m) & uint16(c))

		r[7*i+0] = byte(t0 & 0xff)
		r[7*i+1] = byte(t0>>8) | byte(t1<<6)
		r[7*i+2] = byte(t1 >> 2)
		r[7*i+3] = byte(t1>>10) | byte(t2<<4)
		r[7*i+4] = byte(t2 >> 4)
		r[7*i+5] = byte(t2>>12) | byte(t3<<2)
		r[7*i+6] = byte(t3 >> 6)
	}
}

func (p *poly) discardTo(xbuf []byte) bool {
	var x [shake128Rate * 16 / 2]uint16
	for i := range x {
		x[i] = binary.LittleEndian.Uint16(xbuf[i*2:])
	}

	for i := 0; i < 16; i++ {
		batcher84(x[i:])
	}

	// Check whether we're safe:
	r := int(0)
	for i := 1000; i < 1024; i++ {
		r |= 61444 - int(x[i])
	}
	if r>>31 != 0 {
		return true
	}

	// If we are, copy coefficients to polynomial:
	for i := range p.coeffs {
		p.coeffs[i] = x[i]
	}

	return false
}

func (p *poly) uniform(seed *[SeedBytes]byte, torSampling bool) {
	if !torSampling {
		// Reference version, vartime.
		nBlocks := 14
		var buf [shake128Rate * 14]byte

		// h and buf are left unscrubbed because the output is public.
		h := sha3.NewShake128()
		h.Write(seed[:])
		h.Read(buf[:])

		for ctr, pos := 0, 0; ctr < paramN; {
			val := binary.LittleEndian.Uint16(buf[pos:])

			if val < 5*paramQ {
				p.coeffs[ctr] = val
				ctr++
			}
			pos += 2
			if pos > shake128Rate*nBlocks-2 {
				nBlocks = 1
				h.Read(buf[:shake128Rate])
				pos = 0
			}
		}
	} else {
		// `torref` version, every valid `a` is generate in constant time,
		// though the number of attempts varies.
		const nBlocks = 16
		var buf [shake128Rate * nBlocks]byte

		// h and buf are left unscrubbed because the output is public.
		h := sha3.NewShake128()
		h.Write(seed[:])

		for {
			h.Read(buf[:])
			if !p.discardTo(buf[:]) {
				break
			}
		}

	}
}

func (p *poly) getNoise(seed *[SeedBytes]byte, nonce byte) {
	// The `ref` code uses a uint32 vector instead of a byte vector,
	// but converting between the two in Go is cumbersome.
	var buf [4 * paramN]byte
	var n [8]byte

	n[0] = nonce
	stream, err := chacha20.NewCipher(seed[:], n[:])
	if err != nil {
		panic(err)
	}
	stream.KeyStream(buf[:])
	stream.Reset()

	for i := 0; i < paramN; i++ {
		t := binary.LittleEndian.Uint32(buf[4*i:])
		d := uint32(0)
		for j := uint(0); j < 8; j++ {
			d += (t >> j) & 0x01010101
		}
		a := ((d >> 8) & 0xff) + (d & 0xff)
		b := (d >> 24) + ((d >> 16) & 0xff)
		p.coeffs[i] = uint16(a) + paramQ - uint16(b)
	}

	// Scrub the random bits...
	memwipe(buf[:])
}

func (p *poly) pointwise(a, b *poly) {
	for i := range p.coeffs {
		t := montgomeryReduce(3186 * uint32(b.coeffs[i]))               // t is now in Montgomery domain
		p.coeffs[i] = montgomeryReduce(uint32(a.coeffs[i]) * uint32(t)) // p.coeffs[i] is back in normal domain
	}
}

func (p *poly) add(a, b *poly) {
	for i := range p.coeffs {
		p.coeffs[i] = barrettReduce(a.coeffs[i] + b.coeffs[i])
	}
}

func (p *poly) ntt() {
	p.mulCoefficients(&psisBitrevMontgomery)
	ntt(&p.coeffs, &omegasMontgomery)
}

func (p *poly) invNtt() {
	p.bitrev()
	ntt(&p.coeffs, &omegasInvMontgomery)
	p.mulCoefficients(&psisInvMontgomery)
}

func init() {
	if paramK != 16 {
		panic("poly.getNoise() only supports k=16")
	}
}
