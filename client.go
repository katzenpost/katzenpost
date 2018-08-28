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
)

// Options are optional parameters to configure
// the registration client. Default values are used
// when a nil Options pointer is passed to New.
type Options struct {
	Scheme string
}

var defaultOptions = Options{
	Scheme: "http",
}

// Client handles mixnet Provider account registration.
type Client struct {
	url     *url.URL
	options *Options
}

// New creates a new Client with the provided configuration.
func New(address string, options *Options) *Client {
	if options == nil {
		options = &defaultOptions
	}
	c := &Client{
		url: &url.URL{
			Scheme: options.Scheme,
			Host:   address,
			Path:   registration.URLBase,
		},
		options: options,
	}
	return c
}

func (c *Client) RegisterAccountWithIdentityAndLinkKey(user string, linkKey *ecdh.PublicKey, identityKey *ecdh.PublicKey) error {
	formData := url.Values{
		registration.VersionField:     {registration.Version},
		registration.CommandField:     {registration.RegisterLinkAndIdentityCommand},
		registration.UserField:        {user},
		registration.LinkKeyField:     {linkKey.String()},
		registration.IdentityKeyField: {identityKey.String()},
	}
	response, err := http.PostForm(c.url.String(), formData)
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
	response, err := http.PostForm(c.url.String(), formData)
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("Registration failure: received status code %d", response.StatusCode)
	}
	return nil
}
