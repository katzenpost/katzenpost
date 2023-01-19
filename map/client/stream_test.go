// stream_test.go - map service stream tests
// Copyright (C) 2022  Masala
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
//go:build docker_test
// +build docker_test

package client

import (
	"github.com/katzenpost/katzenpost/client"
	"github.com/katzenpost/katzenpost/client/config"
	"github.com/stretchr/testify/require"
	"io"
	"testing"
)

func TestCreateStream(t *testing.T) {
	require := require.New(t)

	cfg, err := config.LoadFile("testdata/client.toml")
	require.NoError(err)

	cc, err := client.New(cfg)
	require.NoError(err)
	require.NotNil(cc)

	session, err := cc.NewTOFUSession()
	require.NoError(err)
	require.NotNil(session)
	session.WaitForDocument()

	c, err := NewClient(session)
	require.NoError(err)
	require.NotNil(c)

	mysecret := "initiator"
	theirsecret := "receiver"

	// our view of stream
	s := NewStream(c, mysecret, theirsecret)
	// "other end" of stream
	r := NewStream(c, theirsecret, mysecret)

	msg := []byte("Hello World")
	n, err := s.Write(msg)
	require.NoError(err)
	require.Equal(n, len(msg))

	yolo := make([]byte, len(msg))
	for {
		// XXX: the tricky part is that we don't have a convenience method that will handle spinning on Read() for us and
		// ReadAtLeast payload
		// I thought io.ReadAtLeast would do this, but we get EOF too soon
		// because we are just proxying the calls through bytes.Buffer and whatever it does
		n, err = r.Read(yolo)
		if n == len(msg) {
			break
		}
	}
	require.NoError(err)
	require.Equal(n, len(msg))
	require.Equal(yolo, msg)

	msg = []byte("Goodbye World")
	n, err = s.Write(msg)
	require.NoError(err)
	require.Equal(n, len(msg))

	yolo = make([]byte, len(msg))
	n, err = io.ReadAtLeast(r, yolo, len(msg))
	/*
	for {
		n, err = r.Read(yolo)
		if n == len(msg) {
			break
		}
	}
	*/
	require.NoError(err)
	require.Equal(n, len(msg))
	require.Equal(yolo, msg)
}
