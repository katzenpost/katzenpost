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

// Package crypto provides core cryptographic functionality for the Reunion protocol.
package crypto

import (
	"encoding/binary"
	"errors"
	"time"

	"crypto/sha256"
	"github.com/katzenpost/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// HashFunc implements the Hash interface
// as defined in https://godoc.org/hash#Hash
// We use it below in our HKDF construction.
var HashFunc = sha256.New

const (
	// PayloadSize is the size of the Reunion protocol payload.
	PayloadSize = 1000

	// SymmetricKeySize is the size of the symmetric keys we use.
	SymmetricKeySize = 32

	t1AlphaSize = SPRPMinimumBlockLength
	t1BetaSize  = SymmetricKeySize + chacha20poly1305.Overhead
	t1GammaSize = PayloadSize + chacha20poly1305.Overhead

	// Type1MessageSize is the size in bytes of the Type 1 Message.
	Type1MessageSize = t1AlphaSize + t1BetaSize + t1GammaSize

	// Type2MessageSize is the size in bytes of the Type 2 Message.
	Type2MessageSize = SPRPMinimumBlockLength

	// Type3MessageSize is the size in bytes of the Type 3 Message.
	Type3MessageSize = SymmetricKeySize
)

// ErrInvalidMessageSize is an error indicating an invalid message size.
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

func removeMessagePadding(message []byte) ([]byte, error) {
	messageSize := binary.BigEndian.Uint32(message[:4])
	if int(messageSize) > len(message)-4 {
		return nil, errors.New("invalid padding")
	}
	return message[4 : messageSize+4], nil
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

// getSalt returns the salt value composed of:
// GMT_MIDNIGHT || SharedRandom || EpochID
func getSalt(sharedRandomValue []byte, epoch uint64) []byte {
	out := []byte{}
	out = append(out, getLatestMidnight()...)
	out = append(out, sharedRandomValue...)
	var tmp [8]byte
	binary.BigEndian.PutUint64(tmp[:], epoch)
	out = append(out, tmp[:]...)
	return out
}

func newT1Beta(pubKey, secretKey *[32]byte) ([]byte, error) {
	aead1, err := chacha20poly1305.New(secretKey[:])
	if err != nil {
		return nil, err
	}
	ad := []byte{}
	nonce := [chacha20poly1305.NonceSize]byte{}
	beta := []byte{}
	beta = aead1.Seal(beta, nonce[:], pubKey[:], ad)
	return beta, nil
}

func newT1Gamma(message []byte, secretKey *[32]byte) ([]byte, error) {
	payload, err := padMessage(message)
	if err != nil {
		return nil, err
	}

	aead, err := chacha20poly1305.New(secretKey[:])
	if err != nil {
		return nil, err
	}
	nonce := [chacha20poly1305.NonceSize]byte{}
	gamma := []byte{}
	ad := []byte{}
	gamma = aead.Seal(gamma, nonce[:], payload[:], ad)
	return gamma, nil
}

// DecodeT1Message upon success returns alpha, beta, gamma
func DecodeT1Message(message []byte) ([]byte, []byte, []byte, error) {
	if len(message) != Type1MessageSize {
		return nil, nil, nil, errors.New("t1 message has invalid length")
	}
	alpha := message[:t1AlphaSize]
	beta := message[t1AlphaSize : t1AlphaSize+t1BetaSize]
	gamma := message[t1AlphaSize+t1BetaSize:]
	return alpha, beta, gamma, nil
}

// DecryptT1Beta decrypts the Beta portion of a T1 message.
func DecryptT1Beta(candidateKey []byte, t1Beta []byte) (*PublicKey, error) {
	aead, err := chacha20poly1305.New(candidateKey)
	if err != nil {
		return nil, err
	}
	nonce := [chacha20poly1305.NonceSize]byte{}
	ad := []byte{}
	dst := []byte{}
	dst, err = aead.Open(dst, nonce[:], t1Beta, ad)
	if err != nil {
		return nil, err
	}
	return NewPublicKey(dst)
}

func deriveSprpKey(typeName string, sharedRandomValue []byte, epoch uint64, sharedEpochKey []byte) (*[SPRPKeyLength]byte, []byte, error) {
	hkdfContext := []byte(typeName)
	var tmp [8]byte
	binary.BigEndian.PutUint64(tmp[:], epoch)
	hkdfContext = append(hkdfContext, tmp[:]...)

	// hkdf extract and expand
	salt := getSalt(sharedRandomValue, epoch)
	prk := hkdf.Extract(HashFunc, sharedEpochKey, salt)
	kdfReader := hkdf.Expand(HashFunc, prk, hkdfContext)
	key := [SPRPKeyLength]byte{}
	_, err := kdfReader.Read(key[:])
	if err != nil {
		return nil, nil, err
	}
	return &key, hkdfContext, nil
}

func decryptT1Gamma(key []byte, ciphertext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	nonce := [chacha20poly1305.NonceSize]byte{}
	ad := []byte{}
	dst := []byte{}
	plaintext, err := aead.Open(dst, nonce[:], ciphertext, ad)
	if err != nil {
		return nil, err
	}
	return removeMessagePadding(plaintext)
}
