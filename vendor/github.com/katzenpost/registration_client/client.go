// client.go - Katzenpost client registration library
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

// Package client provides a library for registering Katzenpost
// clients with a specific mixnet Provider.
package client

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/server/registration"
	"golang.org/x/net/proxy"
)

// Options are optional parameters to configure
// the registration client. Default values are used
// when a nil Options pointer is passed to New.
type Options struct {
	// Scheme selects the HTTP scheme
	// which is either HTTP or HTTPS
	Scheme string

	// UseSocks is set to true if the specified
	// SOCKS proxy is to be used for dialing.
	UseSocks bool

	// SocksNetwork is the network that the
	// optional SOCKS port is listening on
	// which is usually "unix" or "tcp".
	SocksNetwork string

	// SocksAddress is the address of the SOCKS port.
	SocksAddress string
}

var defaultOptions = Options{
	Scheme: "https",
}

// Client handles mixnet Provider account registration.
type Client struct {
	url     *url.URL
	options *Options
	client  *http.Client
}

// New creates a new Client with the provided configuration.
func New(address string, options *Options) (*Client, error) {
	if options == nil {
		options = &defaultOptions
	}
	client := new(http.Client)
	if options.UseSocks {
		dialer, err := proxy.SOCKS5(options.SocksNetwork, options.SocksAddress, nil, proxy.Direct)
		if err != nil {
			return nil, err
		}
		tr := &http.Transport{
			Dial: dialer.Dial,
		}
		client = &http.Client{Transport: tr}
	}
	c := &Client{
		url: &url.URL{
			Scheme: options.Scheme,
			Host:   address,
			Path:   registration.URLBase,
		},
		options: options,
		client:  client,
	}
	return c, nil
}

func (c *Client) RegisterAccountWithIdentityAndLinkKey(user string, linkKey *ecdh.PublicKey, identityKey *ecdh.PublicKey) error {
	formData := url.Values{
		registration.VersionField:     {registration.Version},
		registration.CommandField:     {registration.RegisterLinkAndIdentityCommand},
		registration.UserField:        {user},
		registration.LinkKeyField:     {linkKey.String()},
		registration.IdentityKeyField: {identityKey.String()},
	}
	response, err := c.client.PostForm(c.url.String(), formData)
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("Registration failure: received status code %d", response.StatusCode)
	}
	return nil
}

func (c *Client) RegisterAccountWithLinkKey(user string, linkKey *ecdh.PublicKey) error {
	formData := url.Values{
		registration.VersionField: {registration.Version},
		registration.CommandField: {registration.RegisterLinkCommand},
		registration.UserField:    {user},
		registration.LinkKeyField: {linkKey.String()},
	}
	response, err := c.client.PostForm(c.url.String(), formData)
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("Registration failure: received status code %d", response.StatusCode)
	}
	return nil
}
