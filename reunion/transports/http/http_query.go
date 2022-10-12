// http_query.go - Reunion client query transport for http.
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

// Package http provides the client transport for Reunion DB queries over http.
package http

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/katzenpost/katzenpost/reunion/commands"
)

// Transport is used by Reunion protocol
// clients to send queries to the Reunion DB service
// over HTTP.
type Transport struct {
	url    string
	client *http.Client
}

// NewTransport creates a new Transport given a URL string.
func NewTransport(url string) *Transport {
	return &Transport{
		url:    url,
		client: &http.Client{Timeout: time.Second * 10},
	}
}

// CurrentSharedRandoms returns the valid shared randoms the transport provides
func (k *Transport) CurrentSharedRandoms() ([][]byte, error) {
	return nil, errors.New("NotImplemented")
}

// CurrentEpochs returns the valid epochs the transport provides
func (k *Transport) CurrentEpochs() ([]uint64, error) {
	return nil, errors.New("NotImplemented")
}

// Query sends the command to the destination Reunion DB service over HTTP.
func (k *Transport) Query(command commands.Command) (commands.Command, error) {
	request, err := http.NewRequest("POST", k.url, bytes.NewBuffer(command.ToBytes()))
	if err != nil {
		return nil, fmt.Errorf("HTTPTransport Query error: %s", err.Error())
	}
	response, err := k.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("HTTPTransport Query error: %s", err.Error())
	}
	reply, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("HTTPTransport Query error: %s", err.Error())
	}
	return commands.FromBytes(reply)
}
