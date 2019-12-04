// crypto.go - Reunion Cryptographic core library sans IO.
// Copyright (C) 2019  David Stainton.
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

// Package provides core cryptographic functions for the Reunion protocol.
package crypto

import (
	"encoding/binary"
	"time"

	"crypto/sha256"
	"github.com/katzenpost/core/pki"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

const (
	// PayloadSize is the size of the Reunion protocol payload.
	PayloadSize = 4096
)

type message interface {
	// ToBytes appends the serialized command to slice b, and returns the
	// resulting slice.
	ToBytes(b []byte) []byte
}

type t1Message struct {
	alpha []byte // 32 bytes
	beta  []byte // 32 bytes
	gamma []byte // PayloadSize bytes
}

// NewT1Message returns a new T1 Message
func NewT1Message(elligatorPubKey *[32]byte, passphrase []byte, crs string, secretKey1, secretKey2 *[32]byte) []byte {
	return nil // XXX
}

type t2Message struct{}

type t3Message struct{}

func kdf(commonReferenceString []byte, passphrase []byte, epoch uint64) ([]byte, error) {
	hashFunc := sha256.New // XXX or what?
	salt := commonReferenceString
	t := uint32(9001)
	memory := uint32(9001)
	threads := uint8(1)
	keyLen := uint32(32)
	keyStretched := argon2.IDKey(passphrase, salt, t, memory, threads, keyLen)
	prk1 := hkdf.Extract(hashFunc, keyStretched, salt)

	// XXX should we also bind the Reunion server identity?
	hkdfContext1 := []byte("type 1")
	var rawEpoch [8]byte
	binary.BigEndian.PutUint64(rawEpoch[:], epoch)
	hkdfContext1 = append(hkdfContext1, rawEpoch[:]...)

	kdfReader := hkdf.Expand(hashFunc, prk1, hkdfContext1)
	key := [32]byte{}
	_, err := kdfReader.Read(key[:])
	if err != nil {
		return nil, err
	}
	return key[:], nil
}

// getLatestMidnight returns the big endian byte slice of the
// unix epoch seconds since the recent UTC midnight.
func getLatestMidnight() []byte {
	y, m, d := time.Now().Date()
	t := time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
	unixSecs := t.Unix()
	var tmp [8]byte
	binary.BigEndian.PutUint64(tmp[:], uint64(unixSecs))
	return tmp[:]
}

// getCommonReferenceString returns the common reference string.
// CRS = GMT_MIDNIGHT || SharedRandom || EpochID
// XXX TODO: append the Reunion server instance ID.
func getCommonReferenceString(doc *pki.Document) []byte {
	out := []byte{}
	out = append(out, getLatestMidnight()...)
	out = append(out, doc.SharedRandomValue...)
	var tmp [8]byte
	binary.BigEndian.PutUint64(tmp[:], doc.Epoch)
	out = append(out, tmp[:]...)
	return out
}
