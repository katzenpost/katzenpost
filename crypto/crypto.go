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
	"errors"
	"time"

	"crypto/sha256"
	"github.com/katzenpost/chacha20poly1305"
	"github.com/katzenpost/core/crypto/rand"
	"golang.org/x/crypto/hkdf"
)

var HashFunc = sha256.New

const (
	// PayloadSize is the size of the Reunion protocol payload.
	PayloadSize = 1000

	// SymmetricKeySize is the size of the symmetric keys we use.
	SymmetricKeySize = 32

	t1AlphaSize = SPRPMinimumBlockLenth
	t1BetaSize  = SymmetricKeySize + chacha20poly1305.NonceSize + chacha20poly1305.Overhead
	t1GammaSize = PayloadSize + chacha20poly1305.NonceSize + chacha20poly1305.Overhead

	// Type1MessageSize is the size in byte of the Type 1 Message.
	Type1MessageSize = t1AlphaSize + t1BetaSize + t1GammaSize
)

var ErrInvalidMessageSize = errors.New("invalid message size")

func padMessage(message []byte) (*[PayloadSize]byte, error) {
	if len(message) > PayloadSize-4 {
		return nil, ErrInvalidMessageSize
	}
	payload := [PayloadSize]byte{}
	binary.BigEndian.PutUint32(payload[:4], uint32(len(message)))
	copy(payload[4:], message)
	return &payload, nil
}

func kdf(commonReferenceString []byte, sharedEpochKey []byte, epoch uint64) ([]byte, error) {
	salt := commonReferenceString
	prk1 := hkdf.Extract(HashFunc, sharedEpochKey, salt)

	// XXX should we also bind the Reunion server identity?
	hkdfContext1 := []byte("type 1")
	var rawEpoch [8]byte
	binary.BigEndian.PutUint64(rawEpoch[:], epoch)
	hkdfContext1 = append(hkdfContext1, rawEpoch[:]...)

	kdfReader := hkdf.Expand(HashFunc, prk1, hkdfContext1)
	key := [SPRPKeyLength]byte{}
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
func getCommonReferenceString(sharedRandomValue []byte, epoch uint64) []byte {
	out := []byte{}
	out = append(out, getLatestMidnight()...)
	out = append(out, sharedRandomValue...)
	var tmp [8]byte
	binary.BigEndian.PutUint64(tmp[:], epoch)
	out = append(out, tmp[:]...)
	return out
}

func newT1Beta(elligatorPubKey, secretKey *[32]byte) ([]byte, error) {
	aead1, err := chacha20poly1305.New(secretKey[:])
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
	beta = aead1.Seal(beta, nonce1[:], elligatorPubKey[:], ad)
	beta = append(beta, nonce1[:]...)
	return beta, nil
}

func newT1Gamma(message []byte, secretKey *[32]byte) ([]byte, error) {
	payload, err := padMessage(message)
	if err != nil {
		return nil, err
	}

	aead2, err := chacha20poly1305.New(secretKey[:])
	if err != nil {
		return nil, err
	}
	nonce2 := [chacha20poly1305.NonceSize]byte{}
	_, err = rand.Reader.Read(nonce2[:])
	if err != nil {
		return nil, err
	}
	gamma := []byte{}
	ad := []byte{}
	gamma = aead2.Seal(gamma, nonce2[:], payload[:], ad)
	gamma = append(gamma, nonce2[:]...)
	return gamma, nil
}

// decodeT1Message upon success returns alpha, beta, gamma
func decodeT1Message(message []byte) ([]byte, []byte, []byte, error) {
	if len(message) != Type1MessageSize {
		return nil, nil, nil, errors.New("t1 message has invalid length")
	}
	alpha := message[:t1AlphaSize]
	beta := message[t1AlphaSize : t1AlphaSize+t1BetaSize]
	gamma := message[t1AlphaSize+t1BetaSize:]
	return alpha, beta, gamma, nil
}

func decryptT1Beta(candidateKey []byte, t1Beta []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(candidateKey)
	if err != nil {
		return nil, err
	}
	nonce := [chacha20poly1305.NonceSize]byte{}
	ad := []byte{}
	dst, err := aead.Open([]byte{}, nonce[:], t1Beta, ad)
	if err != nil {
		return nil, err
	}
	return dst, nil
}
