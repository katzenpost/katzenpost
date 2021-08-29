// client.go - client of cbor plugin system for katzenpost clients
// Copyright (C) 2021  David Stainton.
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

// Package cborplugin is a plugin system allowing mix network services
// to be added in any language. It communicates queries and responses to and from
// the mix server using CBOR over HTTP over UNIX domain socket. Beyond that,
// a client supplied SURB is used to route the response back to the client
// as described in our Kaetzchen specification document:
//
// https://github.com/katzenpost/docs/blob/master/specs/kaetzchen.rst
//
package cborplugin

import (
	"github.com/katzenpost/core/cborplugin"
	"github.com/katzenpost/core/log"
)

type Client struct {
	cborplugin.Client
}

// New creates a new plugin client instance which represents the single execution
// of the external plugin program.
func New(logBackend *log.Backend, commandBuilder cborplugin.CommandBuilder) *Client {
	return &Client{
		Client: *(cborplugin.NewClient(logBackend, commandBuilder)),
	}
}
