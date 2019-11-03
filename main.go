// main.go - Katzenpost ping tool
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

package main

import (
	"context"
	"flag"
	"fmt"
	mrand "math/rand"
	"net/url"
	"strings"
	"time"

	"github.com/katzenpost/client"
	"github.com/katzenpost/client/config"
	clientConfig "github.com/katzenpost/client/config"
	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/core/epochtime"
	"github.com/katzenpost/core/log"
	"github.com/katzenpost/core/pki"
	registration "github.com/katzenpost/registration_client"
)

const (
	initialPKIConsensusTimeout = 45 * time.Second
)

func randUser() string {
	user := [32]byte{}
	_, err := rand.Reader.Read(user[:])
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf("%x", user[:])
}

func register(cfg *config.Config) (*config.Config, *ecdh.PrivateKey) {
	// Retrieve a copy of the PKI consensus document.
	logFilePath := ""
	backendLog, err := log.New(logFilePath, "DEBUG", false)
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

	// Register with that Provider.
	fmt.Println("registering client with mixnet Provider")
	linkKey, err := ecdh.NewKeypair(rand.Reader)
	if err != nil {
		panic(err)
	}
	account := &clientConfig.Account{
		User:           fmt.Sprintf("%x", linkKey.PublicKey().Bytes()),
		Provider:       registrationProvider.Name,
		ProviderKeyPin: registrationProvider.IdentityKey,
	}

	u, err := url.Parse(registrationProvider.RegistrationHTTPAddresses[0])
	if err != nil {
		panic(err)
	}
	registration := &clientConfig.Registration{
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

func main() {
	var configFile string
	var service string
	flag.StringVar(&configFile, "c", "", "configuration file")
	flag.StringVar(&service, "s", "", "service name")
	flag.Parse()

	if service == "" {
		panic("must specify service name with -s")
	}

	cfg, err := config.LoadFile(configFile)
	if err != nil {
		panic(err)
	}
	cfg, linkKey := register(cfg)

	// create a client and connect to the mixnet Provider
	c, err := client.New(cfg)
	if err != nil {
		panic(err)
	}
	s, err := c.NewSession(linkKey)
	if err != nil {
		panic(err)
	}

	serviceDesc, err := s.GetService(service)
	if err != nil {
		panic(err)
	}
	fmt.Printf("sending ping to %s@%s\n", serviceDesc.Name, serviceDesc.Provider)

	mesg, err := s.SendUnreliableMessage(serviceDesc.Name, serviceDesc.Provider, []byte("hello"))
	if err != nil {
		panic(err)
	}
	fmt.Printf("reply: %s\n", mesg)
	fmt.Println("Done. Shutting down.")
	c.Shutdown()
}
