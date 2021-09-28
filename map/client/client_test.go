// client_test.go - map service client tests
// Copyright (C) 2021  Masala
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
// +build docker_test

package client

import (
	"testing"
	"time"

	"github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/client"
	"github.com/katzenpost/katzenpost/map/common"
	"github.com/katzenpost/katzenpost/core/crypto/rand"
	"github.com/stretchr/testify/require"
)

func TestCreateMap(t *testing.T) {
	require := require.New(t)

        cfg, err := config.LoadFile("testdata/client.toml")
        require.NoError(err)

        cfg, linkKey, err := client.NewEphemeralClientConfig(cfg)
        require.NoError(err)

        client, err := client.New(cfg)
        require.NoError(err)

        session, err := client.NewSession(linkKey)
        require.NoError(err)

	c, err := NewClient(session)
	require.NoError(err)
	require.NotNil(c)

	// test creating and retrieving an item

	var id common.MessageID
	_, err = rand.Reader.Read(id[:])
	require.NoError(err)
	payload := []byte("wtf man")
	err = c.Put(id, payload)
	// XXX: we should have a finite number of retransmissions allowed
	// calls to Put are nonblocking but do retry until the message is written.
	// so we need to wait long enough for the command to have arrived. ...
	<-time.After(30*time.Second)

	require.NoError(err)
	resp, err := c.Get(id)
	require.NoError(err)
	require.NotNil(resp)
	require.Equal(payload, resp)
}
