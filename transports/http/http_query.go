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

// Package katzenpost provides the client ACN transport for Reunion
// DB queries over http.
package http

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/katzenpost/reunion/commands"
)

// HTTPTransport is used by Reunion protocol
// clients to send queries to the Reunion DB service
// over HTTP.
type HTTPTransport struct {
	url    string
	client *http.Client
}

// NewHTTPTransport creates a new HTTPTransport given a URL string.
func NewHTTPTransport(url string) *HTTPTransport {
	return &HTTPTransport{
		url:    url,
		client: &http.Client{Timeout: time.Second * 10},
	}
}

// Query sends the command to the destination Reunion DB service over HTTP.
func (k *HTTPTransport) Query(command commands.Command) (commands.Command, error) {
	rawQuery := command.ToBytes()
	request, err := http.NewRequest("POST", k.url, bytes.NewBuffer(rawQuery))
	if err != nil {
		return nil, err
	}
	response, err := k.client.Do(request)
	if err != nil {
		return nil, err
	}
	reply, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	return commands.FromBytes(reply)
}
