// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"os"
	"sync"
)

type StaticKey struct {
	tlsPrivateKey ed25519.PrivateKey
	keyHash       [sha256.Size]byte

	mu          sync.Mutex
	epoch       uint64
	certificate *tls.Certificate
}

func LoadStaticKey(path string) (*StaticKey, error) {
	seed, err := loadOrGenerateSeed(path)
	if err != nil {
		return nil, err
	}
	return staticKeyFromSeed(seed)
}

func ReadStaticKey(path string) (*StaticKey, error) {
	seed, err := readSeed(path)
	if err != nil {
		return nil, err
	}
	return staticKeyFromSeed(seed)
}

func staticKeyFromSeed(seed []byte) (*StaticKey, error) {
	tlsPrivateKey := ed25519.NewKeyFromSeed(seed)
	clear(seed)
	spki, err := x509.MarshalPKIXPublicKey(tlsPrivateKey.Public())
	if err != nil {
		clear(tlsPrivateKey)
		return nil, err
	}
	return &StaticKey{tlsPrivateKey: tlsPrivateKey, keyHash: sha256.Sum256(spki)}, nil
}

func (k *StaticKey) Hash() []byte {
	keyHash := k.keyHash
	return keyHash[:]
}

func (k *StaticKey) WriteHash(path string) error {
	return os.WriteFile(path, []byte(hex.EncodeToString(k.Hash())+"\n"), 0o644)
}

func (k *StaticKey) Hashes(uint64) ([]byte, error) {
	return k.Hash(), nil
}

func (k *StaticKey) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	now := CurrentEpoch()
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.certificate == nil || k.epoch != now {
		certificate, err := epochCertificate(now, k.tlsPrivateKey)
		if err != nil {
			return nil, err
		}
		k.epoch, k.certificate = now, certificate
	}
	return k.certificate, nil
}
