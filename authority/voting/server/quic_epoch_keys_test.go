// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"net/url"
	"path/filepath"
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
	conn, err := common.DialURL(u, ctx, nil, quicKeyHashes)
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
