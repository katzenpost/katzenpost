// SPDX-License-Identifier: AGPL-3.0-only

package pki

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/kem"
	kemschemes "github.com/katzenpost/hpqc/kem/schemes"
	signschemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/server/config"
	"github.com/katzenpost/katzenpost/server/internal/glue"
)

type clientConfigGlue struct {
	glue.Glue
	cfg *config.Config
}

func (g *clientConfigGlue) Config() *config.Config   { return g.cfg }
func (g *clientConfigGlue) LinkKey() kem.PrivateKey  { return nil }
func (g *clientConfigGlue) LogBackend() *log.Backend { return nil }

func TestPKIClientConfigCarriesLocalAddresses(t *testing.T) {
	addrs := []string{"tcp://192.0.2.1:4242", "tcp://[2001:db8::1]:4242"}
	cfg := &config.Config{
		Server: &config.Server{Addresses: addrs},
		PKI:    &config.PKI{Voting: &config.Voting{}},
		Debug:  &config.Debug{ConnectTimeout: 2000, HandshakeTimeout: 3000},
	}
	c := pkiClientConfig(&clientConfigGlue{cfg: cfg}, kemschemes.ByName("Xwing"), signschemes.ByName("Ed25519 Sphincs+"))
	require.Equal(t, addrs, c.LocalAddresses)
	require.Equal(t, 2, c.DialTimeoutSec)
	require.Equal(t, 3, c.HandshakeTimeoutSec)
}
