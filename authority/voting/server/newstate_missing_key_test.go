// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"testing"

	"github.com/stretchr/testify/require"

	signSchemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/log"
)

func TestNewStateRefusesMissingNodeKey(t *testing.T) {
	for _, name := range []string{"Ed25519", "Ed25519 Sphincs+"} {
		t.Run(name, func(t *testing.T) {
			logBackend, err := log.New("", "DEBUG", false)
			require.NoError(t, err)
			ownPub, _, err := signSchemes.ByName(name).GenerateKey()
			require.NoError(t, err)
			cfg := &config.Config{
				Server: &config.Server{DataDir: t.TempDir(), PKISignatureScheme: name},
				Mixes:  []*config.Node{{Identifier: "ghost", IdentityPublicKeyPem: "ghost.public.pem"}},
			}
			require.Panics(t, func() {
				newState(&Server{cfg: cfg, logBackend: logBackend, identityPublicKey: ownPub})
			})
		})
	}
}
