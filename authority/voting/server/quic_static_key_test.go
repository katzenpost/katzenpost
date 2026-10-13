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
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	signschemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/quic/common"
)

func quicAuthority(t *testing.T, dataDir string) *Server {
	t.Helper()
	return loggedQUICAuthority(t, dataDir, filepath.Join(t.TempDir(), "authority.log"))
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

func authorityQUICKeyHash(t *testing.T, dataDir string) []byte {
	t.Helper()
	seed, err := os.ReadFile(filepath.Join(dataDir, "quic-tls.key"))
	require.NoError(t, err, "the authority keeps no QUIC key in its DataDir")
	require.Len(t, seed, ed25519.SeedSize)
	spki, err := x509.MarshalPKIXPublicKey(ed25519.NewKeyFromSeed(seed).Public())
	require.NoError(t, err)
	h := sha256.Sum256(spki)
	return h[:]
}

func loggedQUICAuthority(t *testing.T, dataDir, logFile string) *Server {
	t.Helper()
	_, identityPrivateKey, err := signschemes.ByName(testSchemeName).GenerateKey()
	require.NoError(t, err)
	backend, err := log.New(logFile, "DEBUG", false)
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

func TestAuthorityQUICListenerPresentsItsStaticKey(t *testing.T) {
	dataDir := t.TempDir()
	logFile := filepath.Join(t.TempDir(), "authority.log")
	addr := startQUICAuthority(t, loggedQUICAuthority(t, dataDir, logFile))
	pin := authorityQUICKeyHash(t, dataDir)
	leaf, err := presentedCertificate(t, addr, pin)
	require.NoError(t, err, "the authority presented a key other than the one in its DataDir")
	now := time.Now()
	require.True(t, !now.Before(leaf.NotBefore) && now.Before(leaf.NotAfter), "validity [%v, %v] does not contain now", leaf.NotBefore, leaf.NotAfter)
	logged, err := os.ReadFile(logFile)
	require.NoError(t, err)
	require.Contains(t, string(logged), "QUIC key hash "+hex.EncodeToString(pin))

	addr = startQUICAuthority(t, quicAuthority(t, dataDir))
	_, err = presentedCertificate(t, addr, pin)
	require.NoError(t, err, "a restarted authority presented a key other than the one in its DataDir")
}

func TestAuthorityQUICListenerKeepsItsIdentityKey(t *testing.T) {
	s := quicAuthority(t, t.TempDir())
	identityPublicKey, identityPrivateKey, err := signschemes.ByName(testSchemeName).GenerateKey()
	require.NoError(t, err)
	s.identityPrivateKey = identityPrivateKey
	identitySecret, err := s.identityPrivateKey.MarshalBinary()
	require.NoError(t, err)
	identitySecret = bytes.Clone(identitySecret)
	addr := startQUICAuthority(t, s)
	_, err = presentedCertificate(t, addr, nil)
	require.NoError(t, err)

	after, err := s.identityPrivateKey.MarshalBinary()
	require.NoError(t, err)
	require.Equal(t, identitySecret, after, "listening changed the identity key's MarshalBinary buffer")
	sig := s.identityPrivateKey.Scheme().Sign(s.identityPrivateKey, []byte("still signs"), nil)
	require.True(t, s.identityPrivateKey.Scheme().Verify(identityPublicKey, []byte("still signs"), sig, nil))
}

func TestAuthorityQUICKeyIsNeverLogged(t *testing.T) {
	dataDir := t.TempDir()
	logFile := filepath.Join(t.TempDir(), "authority.log")
	addr := startQUICAuthority(t, loggedQUICAuthority(t, dataDir, logFile))
	_, err := presentedCertificate(t, addr, nil)
	require.NoError(t, err)
	logged, err := os.ReadFile(logFile)
	require.NoError(t, err)
	require.NotEmpty(t, logged)
	seed, err := os.ReadFile(filepath.Join(dataDir, "quic-tls.key"))
	require.NoError(t, err)
	tlsPrivateKey := ed25519.NewKeyFromSeed(seed)
	for _, secret := range [][]byte{seed, tlsPrivateKey} {
		for _, form := range []string{hex.EncodeToString(secret), base64.StdEncoding.EncodeToString(secret), fmt.Sprintf("%v", secret), string(secret)} {
			require.NotContains(t, string(logged), form, "a QUIC TLS key reached the log")
		}
	}
}
