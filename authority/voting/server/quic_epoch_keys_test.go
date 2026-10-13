// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	signschemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/quic/common"
)

func quicAuthority(t *testing.T, dataDir string) *Server {
	t.Helper()
	_, identityPrivateKey, err := signschemes.ByName(testSchemeName).GenerateKey()
	require.NoError(t, err)
	backend, err := log.New(filepath.Join(t.TempDir(), "authority.log"), "DEBUG", false)
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })
	return &Server{
		cfg:                &config.Config{Server: &config.Server{DataDir: dataDir}},
		log:                backend.GetLogger("server"),
		identityPrivateKey: identityPrivateKey,
		state:              &state{},
		haltedCh:           make(chan interface{}),
	}
}

func startQUICAuthority(t *testing.T, s *Server) string {
	t.Helper()
	s.startListeners([]string{"quic://127.0.0.1:0"})
	require.Len(t, s.listeners, 1)
	t.Cleanup(func() {
		close(s.haltedCh)
		s.listeners[0].Close()
		s.Wait()
	})
	return s.listeners[0].Addr().String()
}

func presentedCertificate(t *testing.T, addr string, quicKeyHashes []byte) (*x509.Certificate, error) {
	t.Helper()
	u, err := url.Parse("quic://" + addr)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := common.DialURL(u, ctx, nil, quicKeyHashes, nil)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return conn.(*common.QuicConn).Conn.ConnectionState().TLS.PeerCertificates[0], nil
}

func TestAuthorityQUICListenerPresentsItsEpochKey(t *testing.T) {
	dataDir := t.TempDir()
	s := quicAuthority(t, dataDir)
	addr := startQUICAuthority(t, s)
	leaf, err := presentedCertificate(t, addr, nil)
	require.NoError(t, err)

	now := common.CurrentEpoch()
	keys, err := common.NewEpochKeys(filepath.Join(dataDir, "quic"), common.CurrentEpoch)
	require.NoError(t, err)
	hashes, err := keys.Hashes(now)
	require.NoError(t, err)
	presented := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	require.Equal(t, hashes[sha256.Size:2*sha256.Size], presented[:], "the authority must present its key for epoch %d from DataDir/quic", now)

	lastEpoch := epochtime.Epoch.Add(time.Duration(now+2) * epochtime.Period())
	require.False(t, leaf.NotAfter.After(lastEpoch), "the authority certificate outlives its epoch window: NotAfter %v > %v", leaf.NotAfter, lastEpoch)
}

type authorityEpochClock struct{ epoch atomic.Uint64 }

func (c *authorityEpochClock) now() uint64 { return c.epoch.Load() }

func TestAuthorityQUICKeyRotatesAcrossEpochs(t *testing.T) {
	dataDir := t.TempDir()
	s := quicAuthority(t, dataDir)
	identityPublicKey, identityPrivateKey, err := signschemes.ByName(testSchemeName).GenerateKey()
	require.NoError(t, err)
	s.identityPrivateKey = identityPrivateKey
	identitySecret, err := s.identityPrivateKey.MarshalBinary()
	require.NoError(t, err)
	identitySecret = bytes.Clone(identitySecret)
	clock := &authorityEpochClock{}
	start := common.CurrentEpoch()
	clock.epoch.Store(start)
	s.quicKeys, err = common.NewEpochKeys(filepath.Join(dataDir, "quic"), clock.now)
	require.NoError(t, err)
	addr := startQUICAuthority(t, s)

	published, err := s.quicKeys.Hashes(start + 1)
	require.NoError(t, err)
	require.Len(t, published, 3*sha256.Size)
	seen := make([][]byte, 0, 4)
	for e := start; e < start+4; e++ {
		clock.epoch.Store(e)
		leaf, err := presentedCertificate(t, addr, nil)
		require.NoError(t, err)
		presented := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
		for _, prior := range seen {
			require.NotEqual(t, prior, presented[:], "the authority presented an earlier epoch's key in epoch %d", e)
		}
		seen = append(seen, presented[:])
		if e <= start+2 {
			_, err = presentedCertificate(t, addr, published)
			require.NoError(t, err, "epoch %d: the key published for epoch %d must still be accepted", e, start+1)
		}
	}
	_, err = presentedCertificate(t, addr, published)
	require.ErrorContains(t, err, "QUIC key does not match", "epoch %d: a key published for epoch %d is still presented", start+3, start+1)

	after, err := s.identityPrivateKey.MarshalBinary()
	require.NoError(t, err)
	require.Equal(t, identitySecret, after, "listening changed the identity key's MarshalBinary buffer")
	sig := s.identityPrivateKey.Scheme().Sign(s.identityPrivateKey, []byte("still signs"), nil)
	require.True(t, s.identityPrivateKey.Scheme().Verify(identityPublicKey, []byte("still signs"), sig, nil))
}

func TestAuthorityQUICKeysAreNeverLogged(t *testing.T) {
	dataDir := t.TempDir()
	_, identityPrivateKey, err := signschemes.ByName(testSchemeName).GenerateKey()
	require.NoError(t, err)
	logFile := filepath.Join(t.TempDir(), "authority.log")
	backend, err := log.New(logFile, "DEBUG", false)
	require.NoError(t, err)
	s := &Server{
		cfg:                &config.Config{Server: &config.Server{DataDir: dataDir}},
		log:                backend.GetLogger("server"),
		identityPrivateKey: identityPrivateKey,
		state:              &state{},
		haltedCh:           make(chan interface{}),
	}
	addr := startQUICAuthority(t, s)
	_, err = presentedCertificate(t, addr, nil)
	require.NoError(t, err)
	_, err = s.quicKeys.Hashes(common.CurrentEpoch() + 1)
	require.NoError(t, err)
	backend.Close()
	logged, err := os.ReadFile(logFile)
	require.NoError(t, err)
	require.NotEmpty(t, logged)
	seeds, err := filepath.Glob(filepath.Join(dataDir, "quic", "quic-tls-*.key"))
	require.NoError(t, err)
	require.Len(t, seeds, 3)
	for _, f := range seeds {
		seed, err := os.ReadFile(f)
		require.NoError(t, err)
		tlsPrivateKey := ed25519.NewKeyFromSeed(seed)
		for _, secret := range [][]byte{seed, tlsPrivateKey} {
			for _, form := range []string{hex.EncodeToString(secret), base64.StdEncoding.EncodeToString(secret), fmt.Sprintf("%v", secret), string(secret)} {
				require.NotContains(t, string(logged), form, "a QUIC TLS key reached the log")
			}
		}
	}
}
