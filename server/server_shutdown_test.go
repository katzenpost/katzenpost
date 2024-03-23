// server_test.go - Katzenpost server tests.
// Copyright (C) 2018  David Stainton.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// Package server provides the Katzenpost server.
package server

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	kempem "github.com/katzenpost/hpqc/kem/pem"
	ecdh "github.com/katzenpost/hpqc/nike/x25519"
	"github.com/katzenpost/hpqc/rand"
	signpem "github.com/katzenpost/hpqc/sign/pem"

	aconfig "github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/cert"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/server/config"
)

func TestServerStartShutdown(t *testing.T) {
	assert := assert.New(t)

	datadir, err := os.MkdirTemp("", "server_data_dir")
	assert.NoError(err)

	authLinkPubKeyPem := "auth_link_pub_key.pem"

	scheme := wire.DefaultScheme
	authLinkPubKey, _, err := scheme.GenerateKeyPair()
	require.NoError(t, err)

	err = kempem.PublicKeyToFile(filepath.Join(datadir, authLinkPubKeyPem), authLinkPubKey)
	require.NoError(t, err)

	authPubkey, _, err := cert.Scheme.GenerateKey()
	require.NoError(t, err)

	authIDPubKeyPem := "auth_id_pub_key.pem"
	authkeyPath := filepath.Join(datadir, authIDPubKeyPem)

	err = signpem.PublicKeyToFile(authkeyPath, authPubkey)
	require.NoError(t, err)

	mixIdPublicKey, mixIdPrivateKey, err := cert.Scheme.GenerateKey()
	require.NoError(t, err)
	err = signpem.PrivateKeyToFile(filepath.Join(datadir, "identity.private.pem"), mixIdPrivateKey)
	require.NoError(t, err)
	err = signpem.PublicKeyToFile(filepath.Join(datadir, "identity.public.pem"), mixIdPublicKey)
	require.NoError(t, err)

	geo := geo.GeometryFromUserForwardPayloadLength(
		ecdh.Scheme(rand.Reader),
		2000,
		true,
		5,
	)

	cfg := config.Config{
		SphinxGeometry: geo,
		Server: &config.Server{
			Identifier: "testserver",
			Addresses:  []string{"127.0.0.1:1234"},
			DataDir:    datadir,
			IsProvider: false,
		},
		Logging: &config.Logging{
			Disable: false,
			File:    "",
			Level:   "DEBUG",
		},
		Provider: nil,
		PKI: &config.PKI{
			Voting: &config.Voting{
				Authorities: []*aconfig.Authority{
					&aconfig.Authority{
						Identifier:        "auth1",
						IdentityPublicKey: authPubkey,
						LinkPublicKey:     authLinkPubKey,
						Addresses:         []string{"127.0.0.1:1234"},
					},
				},
			},
		},
		Management: &config.Management{
			Enable: false,
			Path:   "",
		},
		Debug: &config.Debug{
			NumSphinxWorkers:             1,
			NumProviderWorkers:           0,
			NumKaetzchenWorkers:          1,
			SchedulerExternalMemoryQueue: false,
			SchedulerQueueSize:           0,
			SchedulerMaxBurst:            16,
			UnwrapDelay:                  10,
			ProviderDelay:                0,
			KaetzchenDelay:               750,
			SchedulerSlack:               10,
			SendSlack:                    50,
			DecoySlack:                   15 * 1000,
			ConnectTimeout:               60 * 1000,
			HandshakeTimeout:             30 * 1000,
			ReauthInterval:               30 * 1000,
			SendDecoyTraffic:             false,
			DisableRateLimit:             true,
			GenerateOnly:                 false,
		},
	}

	err = cfg.FixupAndValidate()
	assert.NoError(err)

	s, err := New(&cfg)
	assert.NoError(err)
	s.Shutdown()
}
