// sharedrandom.go - Mixnet PKI interfaces
// Copyright (C) 2022  David Stainton, Yawning Angel, masala.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// Package pki provides the mix network PKI related interfaces and serialization routines

package pki

import (
	"crypto/hmac"
	"encoding/binary"
	"io"

	"golang.org/x/crypto/blake2b"

	"github.com/katzenpost/hpqc/rand"
)

// SharedRandom is a container for commit-and-reveal protocol messages
type SharedRandom struct {
	epoch  uint64
	commit []byte
	reveal []byte
}

// Commit produces a SharedRandom commit value for the given epoch
func (s *SharedRandom) Commit(epoch uint64) ([]byte, error) {
	// pick a random number RN
	// COMMIT = Uint64(epoch) || H(REVEAL)
	// REVEAL = Uint64(epoch) || H(RN)
	rn := make([]byte, 32)
	n, err := io.ReadFull(rand.Reader, rn)
	if err != nil || n != 32 {
		return nil, err
	}
	s.epoch = epoch
	s.commit = make([]byte, SharedRandomLength)
	s.reveal = make([]byte, SharedRandomLength)
	binary.BigEndian.PutUint64(s.reveal, epoch)
	binary.BigEndian.PutUint64(s.commit, epoch)
	reveal := blake2b.Sum256(rn)
	copy(s.reveal[8:], reveal[:])
	commit := blake2b.Sum256(s.reveal)
	copy(s.commit[8:], commit[:])
	return s.commit, nil
}

// GetCommit returns the commit value
func (s *SharedRandom) GetCommit() []byte {
	return s.commit
}

// SetCommit sets the commit value
func (s *SharedRandom) SetCommit(rawCommit []byte) {
	s.epoch = binary.BigEndian.Uint64(rawCommit[0:8])
	s.commit = rawCommit
}

// GetEpoch returns the epoch value
func (s *SharedRandom) GetEpoch() uint64 {
	return s.epoch
}

// Verify checks that the reveal value verifies the commit value
func (s *SharedRandom) Verify(reveal []byte) bool {
	if len(reveal) != SharedRandomLength {
		return false
	}
	epoch := binary.BigEndian.Uint64(reveal[0:8])
	allegedCommit := blake2b.Sum256(reveal)
	if epoch == s.epoch {
		if hmac.Equal(s.commit[8:], allegedCommit[:]) {
			return true
		}
	}
	return false
}

// Reveal returns the reveal value
func (s *SharedRandom) Reveal() []byte {
	return s.reveal
}
