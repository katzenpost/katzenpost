// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/katzenpost/katzenpost/core/epochtime"
)

const (
	epochKeysBehind = 1
	epochKeysAhead  = 2
)

var epochKeyFileRe = regexp.MustCompile(`^quic-tls-(\d+)\.key$`)

type epochKey struct {
	tlsPrivateKey ed25519.PrivateKey
	certificate   *tls.Certificate
	keyHash       [sha256.Size]byte
}

type EpochKeys struct {
	mu       sync.Mutex
	dir      string
	now      func() uint64
	keys     map[uint64]*epochKey
	prunedAt uint64
}

func CurrentEpoch() uint64 {
	epoch, _, _ := epochtime.Now()
	return epoch
}

func NewEpochKeys(dir string, now func() uint64) (*EpochKeys, error) {
	k := &EpochKeys{dir: dir, now: now, keys: make(map[uint64]*epochKey), prunedAt: now()}
	if err := k.purgeStaleFiles(k.prunedAt); err != nil {
		return nil, err
	}
	return k, nil
}

func inWindow(epoch, now uint64) bool {
	return epoch+epochKeysBehind >= now && epoch <= now+epochKeysAhead
}

func (k *EpochKeys) keyFile(epoch uint64) string {
	return filepath.Join(k.dir, fmt.Sprintf("quic-tls-%d.key", epoch))
}

func (k *EpochKeys) purgeStaleFiles(now uint64) error {
	entries, err := os.ReadDir(k.dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		sub := epochKeyFileRe.FindStringSubmatch(entry.Name())
		if sub == nil {
			continue
		}
		epoch, err := strconv.ParseUint(sub[1], 10, 64)
		if err != nil || inWindow(epoch, now) {
			continue
		}
		if err := os.Remove(filepath.Join(k.dir, entry.Name())); err != nil {
			return err
		}
	}
	return nil
}

func (k *EpochKeys) pruneLocked(now uint64) error {
	if k.prunedAt == now {
		return nil
	}
	for epoch, key := range k.keys {
		if inWindow(epoch, now) {
			continue
		}
		clear(key.tlsPrivateKey)
		delete(k.keys, epoch)
	}
	if err := k.purgeStaleFiles(now); err != nil {
		return err
	}
	k.prunedAt = now
	return nil
}

func readSeed(path string) ([]byte, error) {
	seed, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(seed) != ed25519.SeedSize {
		clear(seed)
		return nil, fmt.Errorf("quic: TLS key file %s is %d bytes, want %d", path, len(seed), ed25519.SeedSize)
	}
	return seed, nil
}

func loadOrGenerateSeed(path string) ([]byte, error) {
	seed, err := readSeed(path)
	if !errors.Is(err, os.ErrNotExist) {
		return seed, err
	}
	seed = make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	if err := writeSeed(path, seed); err != nil {
		clear(seed)
		return nil, err
	}
	return seed, nil
}

func writeSeed(path string, seed []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".quic-tls-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, err = f.Write(seed)
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		os.Remove(tmp)
	}
	return err
}

func epochStart(epoch uint64) time.Time {
	return epochtime.Epoch.Add(time.Duration(epoch) * epochtime.Period())
}

func epochCertificate(epoch uint64, tlsPrivateKey ed25519.PrivateKey) (*tls.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, err
	}
	template := x509.Certificate{
		SerialNumber: serial.SetBit(serial, 127, 1),
		NotBefore:    epochStart(max(epoch, epochKeysBehind) - epochKeysBehind),
		NotAfter:     epochStart(epoch + 2),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, tlsPrivateKey.Public(), tlsPrivateKey)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{certDER}, PrivateKey: tlsPrivateKey}, nil
}

func (k *EpochKeys) keyLocked(epoch uint64) (*epochKey, error) {
	if key, ok := k.keys[epoch]; ok {
		return key, nil
	}
	seed, err := loadOrGenerateSeed(k.keyFile(epoch))
	if err != nil {
		return nil, err
	}
	tlsPrivateKey := ed25519.NewKeyFromSeed(seed)
	clear(seed)
	certificate, err := epochCertificate(epoch, tlsPrivateKey)
	if err != nil {
		clear(tlsPrivateKey)
		return nil, err
	}
	spki, err := x509.MarshalPKIXPublicKey(tlsPrivateKey.Public())
	if err != nil {
		clear(tlsPrivateKey)
		return nil, err
	}
	key := &epochKey{tlsPrivateKey: tlsPrivateKey, certificate: certificate, keyHash: sha256.Sum256(spki)}
	k.keys[epoch] = key
	return key, nil
}

func (k *EpochKeys) Hashes(epoch uint64) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	now := k.now()
	if err := k.pruneLocked(now); err != nil {
		return nil, err
	}
	hashes := make([]byte, 0, 3*sha256.Size)
	for e := max(epoch, epochKeysBehind) - epochKeysBehind; e <= epoch+1; e++ {
		if !inWindow(e, now) {
			continue
		}
		key, err := k.keyLocked(e)
		if err != nil {
			return nil, err
		}
		hashes = append(hashes, key.keyHash[:]...)
	}
	return hashes, nil
}

func (k *EpochKeys) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	now := k.now()
	if err := k.pruneLocked(now); err != nil {
		return nil, err
	}
	key, err := k.keyLocked(now)
	if err != nil {
		return nil, err
	}
	return key.certificate, nil
}
