// SPDX-License-Identifier: AGPL-3.0-only

package mixkey

import (
	"errors"
	"io"
)

type replayFilter struct{}

func newReplayFilter(r io.Reader, mLn2 int, p float64) (*replayFilter, error) {
	return nil, errors.New("mixkey: replay filter not implemented")
}

func readReplayFilter(r io.Reader, mLn2 int, p float64) (*replayFilter, error) {
	return nil, errors.New("mixkey: replay filter not implemented")
}

func (f *replayFilter) writeTo(w io.Writer) error {
	return errors.New("mixkey: replay filter not implemented")
}

func (f *replayFilter) MaxEntries() int {
	return 0
}

func (f *replayFilter) Entries() int {
	return 0
}

func (f *replayFilter) TestAndSet(v []byte) bool {
	return false
}
