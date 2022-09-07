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
	"io/ioutil"
	"path/filepath"
	"testing"

	"github.com/katzenpost/katzenpost/core/crypto/eddsa"
	"github.com/katzenpost/katzenpost/core/crypto/rand"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/server/config"
	"github.com/stretchr/testify/assert"
)

func TestServerStartShutdown(t *testing.T) {
	assert := assert.New(t)

	dir, err := ioutil.TempDir("", "server_data_dir")
	assert.NoError(err)

	authLinkPubKeyPem := filepath.Join(dir, "auth_link_pub_key.pem")
	scheme := wire.NewScheme()
	authLinkPrivKey, err := scheme.GenerateKeypair(rand.Reader)
	assert.NoError(err)
	authLinkPrivKey.PublicKey().ToPEMFile(authLinkPubKeyPem)

	authkey, err := eddsa.NewKeypair(rand.Reader)
	assert.NoError(err)
	authKeyStr := authkey.PublicKey().String()
	assert.NoError(err)

	mixIdKey, err := eddsa.NewKeypair(rand.Reader)
	assert.NoError(err)

	cfg := config.Config{
		Server: &config.Server{
			Identifier: "testserver",
			Addresses:  []string{"127.0.0.1:1234"},
			DataDir:    dir,
			IsProvider: false,
		},
		Logging: &config.Logging{
			Disable: false,
			File:    "",
			Level:   "DEBUG",
		},
		Provider: nil,
		PKI: &config.PKI{
			Nonvoting: &config.Nonvoting{
				Address:          "127.0.0.1:3321",
				PublicKey:        authKeyStr,
				LinkPublicKeyPem: authLinkPubKeyPem,
			},
		},
		Management: &config.Management{
			Enable: false,
			Path:   "",
		},
		Debug: &config.Debug{
			IdentityKey:                  mixIdKey,
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
