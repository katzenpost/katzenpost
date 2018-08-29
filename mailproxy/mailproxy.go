// mailproxy.go - Katzenpost mailproxy configuration generator
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

// Package mailproxy provides a library for generating mailproxy
// configuration and key material.
package mailproxy

import (
	"bytes"
	"io/ioutil"
	"path"

	"github.com/BurntSushi/toml"
	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/crypto/eddsa"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/mailproxy/config"
)

const (
	mailproxyConfigName = "mailproxy.toml"
)

type PlaygroundDescriptor struct {
	Provider           string
	AuthorityAddr      string
	AuthorityPublicKey *eddsa.PublicKey
}

// GenerateConfig is used to generate mailproxy configuration
// files including key material in the specific dataDir directory.
// It returns the link layer authentication public key and the
// identity public key or an error upon failure. This function returns
// the public keys so that they may be used with the Provider
// account registration process.
func GenerateConfig(user string, dataDir string, playgroundDesc *PlaygroundDescriptor) (*ecdh.PublicKey, *ecdh.PublicKey, error) {
	proxy := &config.Proxy{
		DataDir: dataDir,
	}
	logging := &config.Logging{} // defaults to stdout logging
	debug := &config.Debug{
		SendDecoyTraffic: true,
	}
	nonvotingAuthority := &config.NonvotingAuthority{
		Address:   playgroundDesc.AuthorityAddr,
		PublicKey: playgroundDesc.AuthorityPublicKey,
	}
	linkPrivateKey, err := ecdh.NewKeypair(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	identityPrivateKey, err := ecdh.NewKeypair(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	account := &config.Account{
		User:        user,
		Provider:    playgroundDesc.Provider,
		Authority:   "playground_authority",
		LinkKey:     linkPrivateKey,
		IdentityKey: identityPrivateKey,
	}
	management := &config.Management{} // defaults to disabled
	upstreamProxy := &config.UpstreamProxy{}
	mailproxyCfg := config.Config{
		Proxy:         proxy,
		Logging:       logging,
		Management:    management,
		UpstreamProxy: upstreamProxy,
		Debug:         debug,
		NonvotingAuthority: map[string]*config.NonvotingAuthority{
			account.Authority: nonvotingAuthority,
		},
		Account: []*config.Account{account},
	}

	err = mailproxyCfg.FixupAndValidate()
	if err != nil {
		return nil, nil, err
	}

	// Serialize the configuration and write it to disk.
	serialized := new(bytes.Buffer)
	if err := toml.NewEncoder(serialized).Encode(mailproxyCfg); err != nil {
		return nil, nil, err
	}
	configPath := path.Join(dataDir, mailproxyConfigName)
	err = ioutil.WriteFile(configPath, serialized.Bytes(), 0600)
	if err != nil {
		return nil, nil, err
	}

	return linkPrivateKey.PublicKey(), identityPrivateKey.PublicKey(), nil
}
