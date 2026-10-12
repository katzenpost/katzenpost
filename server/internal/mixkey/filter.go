// SPDX-License-Identifier: AGPL-3.0-only

package mixkey

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"

	"github.com/dchest/siphash"
)

const maxFilterHashes = 32

type replayFilter struct {
	b       []byte
	mask    uint64
	k1, k2  uint64
	hashes  int
	max     int
	entries int
}

func newReplayFilter(r io.Reader, mLn2 int, p float64) (*replayFilter, error) {
	var key [16]byte
	if _, err := io.ReadFull(r, key[:]); err != nil {
		return nil, err
	}
	if p <= 0 || p >= 1 {
		return nil, fmt.Errorf("mixkey: invalid false positive rate: %v", p)
	}
	if mLn2 < 3 || mLn2 > 40 {
		return nil, fmt.Errorf("mixkey: invalid filter size: %d", mLn2)
	}
	m := 1 << uint(mLn2)
	n := -float64(m) * math.Ln2 * math.Ln2 / math.Log(p)
	k := int(float64(m)*math.Ln2/n + 0.5)
	if k > maxFilterHashes {
		return nil, errors.New("mixkey: filter parameters need too many hashes")
	}
	return &replayFilter{
		b:      make([]byte, m/8),
		mask:   uint64(m - 1),
		k1:     binary.BigEndian.Uint64(key[0:8]),
		k2:     binary.BigEndian.Uint64(key[8:16]),
		hashes: max(k, 2),
		max:    int(n),
	}, nil
}

func readReplayFilter(r io.Reader, mLn2 int, p float64) (*replayFilter, error) {
	f, err := newReplayFilter(r, mLn2, p)
	if err != nil {
		return nil, err
	}
	var n [8]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return nil, err
	}
	entries := binary.BigEndian.Uint64(n[:])
	if entries > uint64(f.max) {
		return nil, fmt.Errorf("mixkey: filter claims %d entries, capacity %d", entries, f.max)
	}
	f.entries = int(entries)
	if _, err := io.ReadFull(r, f.b); err != nil {
		return nil, err
	}
	return f, nil
}

func (f *replayFilter) writeTo(w io.Writer) error {
	var hdr [24]byte
	binary.BigEndian.PutUint64(hdr[0:8], f.k1)
	binary.BigEndian.PutUint64(hdr[8:16], f.k2)
	binary.BigEndian.PutUint64(hdr[16:24], uint64(f.entries))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(f.b)
	return err
}

func (f *replayFilter) MaxEntries() int {
	return f.max
}

func (f *replayFilter) Entries() int {
	return f.entries
}

func (f *replayFilter) TestAndSet(v []byte) bool {
	var h [maxFilterHashes]uint64
	h[0], h[1] = siphash.Hash128(f.k1, f.k2, v)
	for i := 2; i < f.hashes; i++ {
		h[i] = h[0] + uint64(i)*h[1]
	}
	present := true
	for i := 0; i < f.hashes; i++ {
		idx := h[i] & f.mask
		bit := byte(1) << (idx & 7)
		present = present && f.b[idx/8]&bit != 0
		f.b[idx/8] |= bit
	}
	if !present {
		f.entries++
	}
	return present
}
