// main.go - main function of client
// Copyright (C) 2019  David Stainton.
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
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/katzenpost/catshadow"
	"github.com/katzenpost/catshadow/config"
	"github.com/katzenpost/client"
	clientConfig "github.com/katzenpost/client/config"
	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/core/epochtime"
	"github.com/katzenpost/core/pki"
	registration "github.com/katzenpost/registration_client"
	"golang.org/x/crypto/ssh/terminal"
	"gopkg.in/op/go-logging.v1"
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

func main() {
	generate := flag.Bool("g", false, "Generate the state file and then run client.")
	cfgFile := flag.String("f", "katzenpost.toml", "Path to the client config file.")
	stateFile := flag.String("s", "catshadow_statefile", "The catshadow state file path.")
	flag.Parse()

	// Set the umask to something "paranoid".
	syscall.Umask(0077)

	fmt.Println("Katzenpost is still pre-alpha.  DO NOT DEPEND ON IT FOR STRONG SECURITY OR ANONYMITY.")

	// Load config file.
	catshadowCfg, err := config.LoadFile(*cfgFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config file '%v': %v\n", *cfgFile, err)
		os.Exit(-1)
	}

	// Decrypt and load the state file.
	fmt.Print("Enter statefile decryption passphrase: ")
	passphrase, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		panic(err)
	}
	fmt.Print("\n")

	var stateWorker *catshadow.StateWriter
	var state *catshadow.State
	var catShadowClient *catshadow.Client
	cfg, err := catshadowCfg.ClientConfig()
	if err != nil {
		panic(err)
	}

	var shellLog *logging.Logger = nil
	if *generate {
		if _, err := os.Stat(*stateFile); !os.IsNotExist(err) {
			panic("cannot generate state file, already exists")
		}

		// Retrieve a copy of the PKI consensus document.
		proxyCfg := cfg.UpstreamProxyConfig()
		backendLog, err := catshadowCfg.InitLogBackend()
		if err != nil {
			panic(err)
		}
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
		user := randUser()
		account := &clientConfig.Account{
			User:           user,
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
		c, err := client.New(cfg)
		if err != nil {
			panic(err)
		}
		linkKey, err := ecdh.NewKeypair(rand.Reader)
		if err != nil {
			panic(err)
		}
		err = client.RegisterClient(cfg, linkKey.PublicKey())
		if err != nil {
			panic(err)
		}

		// XXX Create statefile.
		stateWorker, err = catshadow.NewStateWriter(c.GetLogger("catshadow_state"), *stateFile, passphrase)
		if err != nil {
			panic(err)
		}
		fmt.Println("creating remote message receiver spool")
		catShadowClient, err = catshadow.NewClientAndRemoteSpool(c.GetBackendLog(), c, stateWorker, user, linkKey)
		if err != nil {
			panic(err)
		}
		fmt.Println("catshadow client successfully created")
		shellLog = c.GetLogger("catshadow_shell")
	} else {
		c, err := client.New(cfg)
		if err != nil {
			panic(err)
		}
		shellLog = c.GetLogger("catshadow_shell")
		stateWorker, state, err = catshadow.LoadStateWriter(c.GetLogger("catshadow_state"), *stateFile, passphrase)
		if err != nil {
			panic(err)
		}
		catShadowClient, err = catshadow.New(c.GetBackendLog(), c, stateWorker, state)
		if err != nil {
			panic(err)
		}
	}

	stateWorker.Start()
	fmt.Println("state worker started")
	catShadowClient.Start()
	fmt.Println("catshadow worker started")
	fmt.Println("starting shell")
	shell := NewShell(catShadowClient, shellLog)
	shell.Run()
}
