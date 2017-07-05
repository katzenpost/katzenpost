// client.go - Mixnet client using Noise based wire protocol.
// Copyright (C) 2017  David Anthony Stainton
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

// Package client provides the Katzenpost client side.
package client

type Config struct {
	// LongtermX25519PublicKey is the client's longterm X25519 public key
	// used for private communication between mixnet clients
	LongtermX25519PublicKey *[32]byte

	// LongtermX25519PrivateKey is the client's longterm X25519 private key
	// used for private communication between mixnet clients
	LongtermX25519PrivateKey *[32]byte
}

type Client struct {
	config *Config
}

func New(config *Config) *Client {
	client := Client{
		config: config,
	}
	return &client
}
