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
	"fmt"
	"io/ioutil"
	"path/filepath"

	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/core/utils"
	"golang.org/x/text/secure/precis"
)

const (
	mailproxyConfigName = "mailproxy.toml"
)

func makeConfig(user, provider, providerKey, authority, onionAuthority, authorityKey, dataDir, socksNet, socksAddr string, preferOnion bool) []byte {
	configFormatStr := `
[Proxy]
  POP3Address = "127.0.0.1:2524"
  SMTPAddress = "127.0.0.1:2525"
  DataDir = "%s"

[Logging]
  Disable = false
  Level = "NOTICE"

[NonvotingAuthority]
  [NonvotingAuthority.PlaygroundAuthority]
    Address = "%s"
    PublicKey = "%s"

[[Account]]
  User = "%s"
  Provider = "%s"
  ProviderKeyPin = "%s"
  NonvotingAuthority = "PlaygroundAuthority"
  InsecureKeyDiscovery = true

[Management]
  Enable = false
`

	upstreamProxy := `
[UpstreamProxy]
  PreferedTransports = [ "onion" ]
  Type = "tor+socks5"
  Network = "%s"
  Address = "%s"
`

	if preferOnion {
		output := []byte(fmt.Sprintf(configFormatStr, dataDir, onionAuthority, authorityKey, user, provider, providerKey))
		output = append(output, []byte(fmt.Sprintf(upstreamProxy, socksNet, socksAddr))...)
		return output
	} else {
		return []byte(fmt.Sprintf(configFormatStr, dataDir, authority, authorityKey, user, provider, providerKey))
	}
}

// GenerateConfig is used to generate mailproxy configuration
// files including key material in the specific dataDir directory.
// It returns the link layer authentication public key and the
// identity public key or an error upon failure. This function returns
// the public keys so that they may be used with the Provider
// account registration process.
func GenerateConfig(user, provider, providerKey, authority, onionAuthority, authorityKey, dataDir, socksNet, socksAddr string, preferOnion bool) (*ecdh.PublicKey, *ecdh.PublicKey, error) {
	// Initialize the per-account directory.
	user, err := precis.UsernameCaseMapped.String(user)
	if err != nil {
		return nil, nil, err
	}
	id := fmt.Sprintf("%s@%s", user, provider)
	basePath := filepath.Join(dataDir, id)
	if err := utils.MkDataDir(basePath); err != nil {
		return nil, nil, err
	}

	// generate and write keys to disk
	linkPriv := filepath.Join(basePath, "link.private.pem")
	linkPub := filepath.Join(basePath, "link.public.pem")
	linkPrivateKey, err := ecdh.Load(linkPriv, linkPub, rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	idPriv := filepath.Join(basePath, "identity.private.pem")
	idPub := filepath.Join(basePath, "identity.public.pem")
	identityPrivateKey, err := ecdh.Load(idPriv, idPub, rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	// write the configuration file
	configData := makeConfig(user, provider, providerKey, authority, onionAuthority, authorityKey, dataDir, socksNet, socksAddr, preferOnion)
	configPath := filepath.Join(dataDir, mailproxyConfigName)
	err = ioutil.WriteFile(configPath, configData, 0600)
	if err != nil {
		return nil, nil, err
	}
	return linkPrivateKey.PublicKey(), identityPrivateKey.PublicKey(), nil
}
