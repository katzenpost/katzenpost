// client_server_test.go - Docker integration tests for client and server.
// Copyright (C) 2020  David Stainton.
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

// +build docker_test

package main

import (
	"context"
	"fmt"
	mrand "math/rand"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/katzenpost/client"
	"github.com/katzenpost/client/config"
	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/core/epochtime"
	"github.com/katzenpost/core/log"
	"github.com/katzenpost/core/pki"
	registration "github.com/katzenpost/registration_client"
	reunionClient "github.com/katzenpost/reunion/client"
	catClock "github.com/katzenpost/reunion/epochtime/katzenpost"
	"github.com/katzenpost/reunion/transports/katzenpost"
	"github.com/stretchr/testify/require"
)

const (
	initialPKIConsensusTimeout = 45 * time.Second
)

func register(cfg *config.Config) (*config.Config, *ecdh.PrivateKey) {
	// Retrieve a copy of the PKI consensus document.
	backendLog, err := log.New(cfg.Logging.File, "DEBUG", false)
	if err != nil {
		panic(err)
	}
	proxyCfg := cfg.UpstreamProxyConfig()
	pkiClient, err := cfg.NewPKIClient(backendLog, proxyCfg)
	if err != nil {
		panic(err)
	}
	currentEpoch, _, _ := epochtime.FromUnix(time.Now().Unix())
	ctx, cancel := context.WithTimeout(context.Background(), initialPKIConsensusTimeout)
	defer cancel()
	doc, _, err := pkiClient.Get(ctx, currentEpoch)
	if err != nil {
		panic(err)
	}

	// Pick a registration Provider.
	registerProviders := []*pki.MixDescriptor{}
	for _, provider := range doc.Providers {
		if provider.RegistrationHTTPAddresses != nil {
			registerProviders = append(registerProviders, provider)
		}
	}
	if len(registerProviders) == 0 {
		panic("zero registration Providers found in the consensus")
	}
	registrationProvider := registerProviders[mrand.Intn(len(registerProviders))]

	linkKey, err := ecdh.NewKeypair(rand.Reader)
	if err != nil {
		panic(err)
	}
	account := &config.Account{
		User:           fmt.Sprintf("%x", linkKey.PublicKey().Bytes()),
		Provider:       registrationProvider.Name,
		ProviderKeyPin: registrationProvider.IdentityKey,
	}

	u, err := url.Parse(registrationProvider.RegistrationHTTPAddresses[0])
	if err != nil {
		panic(err)
	}
	registration := &config.Registration{
		Address: u.Host,
		Options: &registration.Options{
			Scheme:       u.Scheme,
			UseSocks:     strings.HasPrefix(cfg.UpstreamProxy.Type, "socks"),
			SocksNetwork: cfg.UpstreamProxy.Network,
			SocksAddress: cfg.UpstreamProxy.Address,
		},
	}
	cfg.Account = account
	cfg.Registration = registration
	err = client.RegisterClient(cfg, linkKey.PublicKey())
	if err != nil {
		panic(err)
	}
	return cfg, linkKey
}

func TestDockerClientExchange(t *testing.T) {
	require := require.New(t)

	cfg, err := config.LoadFile("testdata/catshadow.toml")
	require.NoError(err)
	cfg, linkKey := register(cfg)
	c, err := client.New(cfg)
	require.NoError(err)
	session, err := c.NewSession(linkKey)
	require.NoError(err)
	serviceDesc, err := session.GetService("reunion")
	require.NoError(err)

	transport := &katzenpost.Transport{
		Session:   session,
		Recipient: serviceDesc.Name,
		Provider:  serviceDesc.Provider,
	}
	clock := new(catClock.Clock)
	epoch, _, _ := clock.Now()
	srv := []byte{1, 2, 3}
	passphrase := []byte("blah blah motorcycle pencil sharpening gas tank")

	f := ""
	level := "DEBUG"
	disable := false
	logBackend, err := log.New(f, level, disable)
	require.NoError(err)

	var bobResult []byte
	var aliceResult []byte

	// client Alice

	alicePayload := []byte("Hello Bobby, what's up dude?")
	aliceContactID := uint64(1)
	aliceExchangelog := logBackend.GetLogger("alice_exchange")

	var wg sync.WaitGroup
	wg.Add(1)
	aliceUpdateCh := make(chan reunionClient.ReunionUpdate)
	go func() {
		for {
			update := <-aliceUpdateCh
			if len(update.Result) > 0 {
				aliceResult = update.Result
				fmt.Printf("\n Alice got result: %s\n\n", update.Result)
				wg.Done()
			}
		}
	}()

	aliceExchange, err := reunionClient.NewExchange(alicePayload, aliceExchangelog, transport, aliceContactID, passphrase, srv, epoch, aliceUpdateCh)
	require.NoError(err)

	// bob client
	bobPayload := []byte("yo Alice, so you are a cryptographer and a language designer both?")
	bobContactID := uint64(2)
	bobLogBackend, err := log.New(f, level, disable)
	require.NoError(err)
	bobExchangelog := bobLogBackend.GetLogger("bob_exchange")

	wg.Add(1)
	bobUpdateCh := make(chan reunionClient.ReunionUpdate)
	go func() {
		for {
			update := <-bobUpdateCh
			if len(update.Result) > 0 {
				bobResult = update.Result
				fmt.Printf("\n Bob got result: %s\n\n", update.Result)
				wg.Done()
			}
		}
	}()

	bobExchange, err := reunionClient.NewExchange(bobPayload, bobExchangelog, transport, bobContactID, passphrase, srv, epoch, bobUpdateCh)
	require.NoError(err)

	// Run reunion client exchanges.

	go aliceExchange.Run()
	go bobExchange.Run()

	wg.Wait()

	require.Equal(aliceResult, bobPayload)
	require.Equal(bobResult, alicePayload)
}
