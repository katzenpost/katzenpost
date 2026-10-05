// SPDX-License-Identifier: AGPL-3.0-only

package pki

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/server/config"
)

type newClientGlue struct {
	clientConfigGlue
	backend *log.Backend
}

func (g *newClientGlue) LogBackend() *log.Backend { return g.backend }

func TestNewBuildsTheVotingClient(t *testing.T) {
	backend, err := log.New("", "ERROR", false)
	require.NoError(t, err)
	cfg := &config.Config{
		Server: &config.Server{
			Addresses:          []string{"tcp://192.0.2.1:4242"},
			WireKEM:            "Xwing",
			PKISignatureScheme: "Ed25519 Sphincs+",
		},
		PKI:   &config.PKI{Voting: &config.Voting{}},
		Debug: &config.Debug{ConnectTimeout: 2000, HandshakeTimeout: 3000},
	}
	p, err := New(&newClientGlue{clientConfigGlue: clientConfigGlue{cfg: cfg}, backend: backend})
	require.NoError(t, err)
	require.NotNil(t, p.(*pki).impl)

	cfg.Server.WireKEM = "no-such-kem"
	_, err = New(&newClientGlue{clientConfigGlue: clientConfigGlue{cfg: cfg}, backend: backend})
	require.Error(t, err)
}
