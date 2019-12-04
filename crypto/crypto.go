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
	"github.com/katzenpost/chacha20poly1305"
	"github.com/katzenpost/core/crypto/rand"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

const (
	// PayloadSize is the size of the Reunion protocol payload.
	PayloadSize = 4096
)

func kdf(commonReferenceString []byte, passphrase []byte, epoch uint64) ([]byte, []byte, error) {
	hashFunc := sha256.New
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
	key := [SPRPKeyLength]byte{}
	_, err := kdfReader.Read(key[:])
	if err != nil {
		return nil, nil, err
	}
	iv := [SPRPIVLength]byte{}
	_, err = kdfReader.Read(iv[:])
	if err != nil {
		return nil, nil, err
	}
	return key[:], iv[:], nil
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
func getCommonReferenceString(sharedRandomValue []byte, epoch uint64) []byte {
	out := []byte{}
	out = append(out, getLatestMidnight()...)
	out = append(out, sharedRandomValue...)
	var tmp [8]byte
	binary.BigEndian.PutUint64(tmp[:], epoch)
	out = append(out, tmp[:]...)
	return out
}

// NewT1Message returns a new T1 Message
func NewT1Message(elligatorPubKey, a2PubKey *[32]byte, payload, passphrase []byte, secretKey1, secretKey2 *[32]byte, epoch uint64, sharedRandomValue []byte) ([]byte, error) {

	// alpha
	crs := getCommonReferenceString(sharedRandomValue, epoch)
	k1, k1iv, err := kdf(crs, passphrase, epoch)
	if err != nil {
		return nil, err
	}

	key := [SPRPKeyLength]byte{}
	copy(key[:], k1)
	iv := [SPRPIVLength]byte{}
	copy(iv[:], k1iv)
	alpha := SPRPEncrypt(&key, &iv, elligatorPubKey[:])

	// beta
	aead1, err := chacha20poly1305.New(secretKey1[:])
	if err != nil {
		return nil, err
	}
	ad := []byte{}
	nonce1 := [chacha20poly1305.NonceSize]byte{}
	_, err = rand.Reader.Read(nonce1[:])
	if err != nil {
		return nil, err
	}
	beta := []byte{}
	beta = aead1.Seal(beta, nonce1[:], a2PubKey[:], ad)
	beta = append(beta, nonce1[:]...)

	// gamma
	aead2, err := chacha20poly1305.New(secretKey2[:])
	if err != nil {
		return nil, err
	}
	nonce2 := [chacha20poly1305.NonceSize]byte{}
	_, err = rand.Reader.Read(nonce2[:])
	if err != nil {
		return nil, err
	}
	gamma := []byte{}
	gamma = aead2.Seal(gamma, nonce2[:], payload, ad)
	gamma = append(gamma, nonce2[:]...)

	output := []byte{}
	output = append(output, alpha...)
	output = append(output, beta...)
	output = append(output, gamma...)
	return output, nil
}
