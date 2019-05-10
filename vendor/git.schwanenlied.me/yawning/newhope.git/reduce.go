// poly.go - NewHope reductions.
//
// To the extent possible under law, Yawning Angel has waived all copyright
// and related or neighboring rights to newhope, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package newhope

// Incomplete-reduction routines; for details on allowed input ranges
// and produced output ranges, see the description in the paper:
// https://cryptojedi.org/papers/#newhope

const (
	qinv = 12287 // -inverse_mod(p,2^18)
	rlog = 18
)

func montgomeryReduce(a uint32) uint16 {
	u := a * qinv
	u &= ((1 << rlog) - 1)
	u *= paramQ
	a = (a + u) >> 18
	return uint16(a)
}

func barrettReduce(a uint16) uint16 {
	u := (uint32(a) * 5) >> 16
	u *= paramQ
	a -= uint16(u)
	return a
}
