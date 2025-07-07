// bloom.go - Bloom filter.
// Written in 2015 by Yawning Angel
//
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication along
// with this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.

// Package bloom implements a Bloom Filter.
package bloom

import (
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"strconv"

	"github.com/dchest/siphash"
)

const (
	maxNrHashes = 32
	ln2         = 0.69314718055994529
)

// Filter is a bloom filter.
type Filter struct {
	b        []byte
	hashMask uint64

	k1, k2 uint64

	nrHashes     int
	nrEntriesMax int
	nrEntries    int
}

// DeriveSize returns the size of a filter (as a power of 2) in bits,
// required to hold at least n entries with a p false positive rate.
//
// The returned value is directly suitable for use as the mLn2 parameter
// passed to New().
func DeriveSize(n int, p float64) int {
	if n <= 0 {
		panic("negative number of entries")
	}
	if p <= 0.0 || p >= 1.0 {
		panic("invalid false positive rate")
	}
	m := (float64(n) * math.Log(p)) / math.Log(1.0/math.Pow(2.0, ln2))
	return int(math.Ceil(math.Log2(m)))
}

// New constructs a new Filter with a filter set size 2^mLn2 bits, and false
// postive rate p.
func New(rand io.Reader, mLn2 int, p float64) (*Filter, error) {
	const (
		ln2Sq   = 0.48045301391820139
		maxMln2 = strconv.IntSize - 1
	)

	var key [16]byte
	if _, err := io.ReadFull(rand, key[:]); err != nil {
		return nil, err
	}

	if p <= 0.0 || p >= 1.0 {
		return nil, fmt.Errorf("invalid false positive rate: %v", p)
	}

	if mLn2 > maxMln2 {
		return nil, fmt.Errorf("requested filter too large: %d", mLn2)
	}

	m := 1 << uint64(mLn2)
	n := -1.0 * float64(m) * ln2Sq / math.Log(p)
	k := int((float64(m) * ln2 / n) + 0.5)

	if uint64(n) > (1 << uint(maxMln2)) {
		return nil, fmt.Errorf("requested filter too large (nrEntriesMax overflow): %d", mLn2)
	}

	f := new(Filter)
	f.k1 = binary.BigEndian.Uint64(key[0:8])
	f.k2 = binary.BigEndian.Uint64(key[8:16])
	f.nrEntriesMax = int(n)
	f.nrHashes = k
	f.hashMask = uint64(m - 1)
	if f.nrHashes < 2 {
		f.nrHashes = 2
	} else if f.nrHashes > maxNrHashes {
		return nil, fmt.Errorf("requested parameters need too many hashes")
	}
	f.b = make([]byte, m/8)
	return f, nil
}

// MaxEntries returns the maximum capacity of the Filter.
func (f *Filter) MaxEntries() int {
	return f.nrEntriesMax
}

// Entries returns the number of entries that have been inserted into the
// Filter.
func (f *Filter) Entries() int {
	return f.nrEntries
}

// TestAndSet tests the Filter for a given value's membership, adds the value
// to the filter, and returns true iff it was present at the time of the call.
func (f *Filter) TestAndSet(b []byte) bool {
	var hashes [maxNrHashes]uint64
	f.getHashes(b, &hashes)

	// Just return true iff the entry is present.
	if f.test(&hashes) {
		return true
	}

	// Add and return false.
	f.add(&hashes)
	f.nrEntries++
	return false
}

// Test tests the Filter for a given value's membership and returns true iff
// it is present (or a false positive).
func (f *Filter) Test(b []byte) bool {
	var hashes [maxNrHashes]uint64
	f.getHashes(b, &hashes)

	return f.test(&hashes)
}

func (f *Filter) getHashes(b []byte, hashes *[maxNrHashes]uint64) {
	// Per "Less Hashing, Same Performance: Building a Better Bloom Filter"
	// (Kirsch and Miteznmacher), with a suitably good PRF, only two calls to
	// the hash algorithm are needed.  This is done with the "experimental"
	// 128 bit digest variant of SipHash, split into 2 64 bit unsigned
	// integers.

	hashes[0], hashes[1] = siphash.Hash128(f.k1, f.k2, b)
	for i := 2; i < f.nrHashes; i++ {
		hashes[i] = hashes[0] + uint64(i)*hashes[1]
	}
}

func (f *Filter) test(hashes *[maxNrHashes]uint64) bool {
	for i := 0; i < f.nrHashes; i++ {
		idx := hashes[i] & f.hashMask
		if 0 == f.b[idx/8]&(1<<(idx&7)) {
			// Break out early if there is a miss.
			return false
		}
	}
	return true
}

func (f *Filter) add(hashes *[maxNrHashes]uint64) {
	for i := 0; i < f.nrHashes; i++ {
		idx := hashes[i] & f.hashMask
		f.b[idx/8] |= (1 << (idx & 7))
	}
}
