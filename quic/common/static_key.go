// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"os"
	"sync"
)

type StaticKey struct {
	tlsPrivateKey crypto.Signer
	keyHash       [sha256.Size]byte

	mu          sync.Mutex
	epoch       uint64
	certificate *tls.Certificate
}

func LoadStaticKey(path string, opts *Options) (*StaticKey, error) {
	if err := opts.Validate(); err != nil {
		return nil, err
	}
	seed, err := loadOrGenerateSeed(path)
	if err != nil {
		return nil, err
	}
	return staticKeyFromSeed(opts.signature(), seed)
}

func ReadStaticKey(path string, opts *Options) (*StaticKey, error) {
	if err := opts.Validate(); err != nil {
		return nil, err
	}
	seed, err := readSeed(path)
	if err != nil {
		return nil, err
	}
	return staticKeyFromSeed(opts.signature(), seed)
}

func staticKeyFromSeed(signature string, seed []byte) (*StaticKey, error) {
	tlsPrivateKey, err := newTLSKey(signature, seed)
	clear(seed)
	if err != nil {
		return nil, err
	}
	spki, err := x509.MarshalPKIXPublicKey(tlsPrivateKey.Public())
	if err != nil {
		wipeTLSKey(tlsPrivateKey)
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
