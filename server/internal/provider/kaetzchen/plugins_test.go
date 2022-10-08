// plugins_test.go - tests for plugin system
// Copyright (C) 2018  David Stainton
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

package kaetzchen

import (
	"testing"

	"github.com/katzenpost/katzenpost/core/crypto/cert"
	"github.com/katzenpost/katzenpost/core/crypto/rand"
	"github.com/katzenpost/katzenpost/core/crypto/sign"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/server/config"
	"github.com/stretchr/testify/require"
)

func getGlue(logBackend *log.Backend, provider *mockProvider, linkKey wire.PrivateKey, idKey sign.PrivateKey) *mockGlue {
	goo := &mockGlue{
		s: &mockServer{
			logBackend: logBackend,
			provider:   provider,
			linkKey:    linkKey,
			cfg: &config.Config{
				Server:     &config.Server{},
				Logging:    &config.Logging{},
				Provider:   &config.Provider{},
				PKI:        &config.PKI{},
				Management: &config.Management{},
				Debug: &config.Debug{
					NumKaetzchenWorkers: 3,
					KaetzchenDelay:      300,
				},
			},
		},
	}
	return goo
}

func TestCBORInvalidCommandWithPluginKaetzchenWorker(t *testing.T) {
	require := require.New(t)

	idKey, _ := cert.Scheme.NewKeypair()

	logBackend, err := log.New("", "DEBUG", false)
	require.NoError(err)

	scheme := wire.DefaultScheme
	userKey := scheme.GenerateKeypair(rand.Reader)
	linkKey := scheme.GenerateKeypair(rand.Reader)

	mockProvider := &mockProvider{
		userName: "alice",
		userKey:  userKey.PublicKey(),
	}

	goo := getGlue(logBackend, mockProvider, linkKey, idKey)
	goo.s.cfg.Provider.CBORPluginKaetzchen = []*config.CBORPluginKaetzchen{
		&config.CBORPluginKaetzchen{
			Capability:     "echo",
			Endpoint:       "echo",
			Config:         map[string]interface{}{},
			Disable:        false,
			Command:        "non-existent command",
			MaxConcurrency: 1,
		},
	}
	_, err = NewCBORPluginWorker(goo)
	require.Error(err)
}
