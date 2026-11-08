// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	signSchemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/quic/common"
)

func quicKeyServer(t *testing.T, ownQUICKeyHash []byte) *Server {
	t.Helper()
	scheme := signSchemes.ByName(testSchemeName)
	identity, _, err := scheme.GenerateKey()
	require.NoError(t, err)
	other, _, err := scheme.GenerateKey()
	require.NoError(t, err)
	backend, err := log.New("", "ERROR", false)
	require.NoError(t, err)
	return &Server{
		cfg: &config.Config{
			Server: &config.Server{DataDir: t.TempDir()},
			Authorities: []*config.Authority{
				{Identifier: "other", IdentityPublicKey: other, QUICKeyHash: bytes.Repeat([]byte{3}, 32)},
				{Identifier: "self", IdentityPublicKey: identity, QUICKeyHash: ownQUICKeyHash},
			},
		},
		identityPublicKey: identity,
		log:               backend.GetLogger("authority"),
	}
}

func TestAuthorityRefusesToRegenerateAPinnedQUICKey(t *testing.T) {
	s := quicKeyServer(t, bytes.Repeat([]byte{2}, 32))
	_, err := s.quicStaticKey()
	require.ErrorContains(t, err, "quic-tls.key", "a missing quic-tls.key pinned by this authority's own entry was regenerated")
	_, err = os.Stat(filepath.Join(s.cfg.Server.DataDir, "quic-tls.key"))
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestAuthorityRefusesAQUICKeyItsOwnEntryDoesNotPin(t *testing.T) {
	s := quicKeyServer(t, bytes.Repeat([]byte{2}, 32))
	_, err := common.LoadStaticKey(filepath.Join(s.cfg.Server.DataDir, "quic-tls.key"), nil)
	require.NoError(t, err)
	_, err = s.quicStaticKey()
	require.ErrorContains(t, err, "QUICKeyHash", "a quic-tls.key whose hash differs from this authority's own QUICKeyHash was used")
}

func TestAuthorityQUICKeyMatchingItsOwnEntryLoads(t *testing.T) {
	s := quicKeyServer(t, nil)
	key, err := common.LoadStaticKey(filepath.Join(s.cfg.Server.DataDir, "quic-tls.key"), nil)
	require.NoError(t, err)
	s.cfg.Authorities[1].QUICKeyHash = key.Hash()
	loaded, err := s.quicStaticKey()
	require.NoError(t, err)
	require.Equal(t, key.Hash(), loaded.Hash())
}

func TestAuthorityWithoutItsOwnQUICKeyHashGeneratesTheKey(t *testing.T) {
	s := quicKeyServer(t, nil)
	_, err := s.quicStaticKey()
	require.NoError(t, err)
	_, err = os.Stat(filepath.Join(s.cfg.Server.DataDir, "quic-tls.key"))
	require.NoError(t, err)
}
