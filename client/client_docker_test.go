// client_docker_test.go - optional memspool docker test
// Copyright (C) 2019  David Stainton, Masala.
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
	"bytes"
	"testing"

	cc "github.com/katzenpost/client"
	"github.com/katzenpost/client/config"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/memspool/common"
	"github.com/stretchr/testify/require"
)

func TestDockerUnreliableSpoolService(t *testing.T) {
	require := require.New(t)

	cfg, err := config.LoadFile("testdata/client.toml")
	require.NoError(err)

	cfg, linkKey, err := cc.AutoRegisterRandomClient(cfg)
	require.NoError(err)
	client, err := cc.New(cfg)
	require.NoError(err)

	s, err := client.NewSession(linkKey)
	require.NoError(err)

	// look up a spool provider
	desc, err := s.GetService(common.SpoolServiceName)
	require.NoError(err)
	t.Logf("Found spool provider: %v@%v", desc.Name, desc.Provider)

	// create the spool on the remote provider
	spoolReadDescriptor, err := NewSpoolReadDescriptor(desc.Name, desc.Provider, s)
	require.NoError(err)

	// append to a spool
	message := []byte("hello there")
	appendCmd, err := common.AppendToSpool(spoolReadDescriptor.ID, message)
	require.NoError(err)
	rawResponse, err := s.BlockingSendReliableMessage(desc.Name, desc.Provider, appendCmd)
	require.NoError(err)
	response, err := common.SpoolResponseFromBytes(rawResponse)
	require.NoError(err)
	require.True(response.IsOK())

	messageID := uint32(1) // where do we learn messageID?

	// read from a spool (should find our original message)
	readCmd, err := common.ReadFromSpool(spoolReadDescriptor.ID, messageID, spoolReadDescriptor.PrivateKey)
	require.NoError(err)
	rawResponse, err = s.BlockingSendReliableMessage(desc.Name, desc.Provider, readCmd)
	require.NoError(err)
	response, err = common.SpoolResponseFromBytes(rawResponse)
	require.NoError(err)
	require.True(response.IsOK())
	// XXX require.Equal(response.SpoolID, spoolReadDescriptor.ID)
	require.True(bytes.Equal(response.Message, message))

	// purge a spool
	purgeCmd, err := common.PurgeSpool(spoolReadDescriptor.ID, spoolReadDescriptor.PrivateKey)
	require.NoError(err)
	rawResponse, err = s.BlockingSendReliableMessage(desc.Name, desc.Provider, purgeCmd)
	require.NoError(err)
	response, err = common.SpoolResponseFromBytes(rawResponse)
	require.NoError(err)
	require.True(response.IsOK())

	// read from a spool (should be empty?)
	readCmd, err = common.ReadFromSpool(spoolReadDescriptor.ID, messageID, spoolReadDescriptor.PrivateKey)
	require.NoError(err)
	rawResponse, err = s.BlockingSendReliableMessage(desc.Name, desc.Provider, readCmd)
	response, err = common.SpoolResponseFromBytes(rawResponse)
	require.NoError(err)
	require.False(response.IsOK())

	<-s.EventSink

	client.Shutdown()
	client.Wait()
}

func TestDockerUnreliableSpoolServiceMore(t *testing.T) {
	require := require.New(t)

	cfg, err := config.LoadFile("testdata/client.toml")
	require.NoError(err)

	cfg, linkKey, err := cc.AutoRegisterRandomClient(cfg)
	require.NoError(err)
	client, err := cc.New(cfg)
	require.NoError(err)

	s, err := client.NewSession(linkKey)
	require.NoError(err)

	// look up a spool provider
	desc, err := s.GetService(common.SpoolServiceName)
	require.NoError(err)
	t.Logf("Found spool provider: %v@%v", desc.Name, desc.Provider)

	// create the spool on the remote provider
	spoolReadDescriptor, err := NewSpoolReadDescriptor(desc.Name, desc.Provider, s)
	require.NoError(err)
	messageID := uint32(1) // where do we learn messageID?
	for i := 0; i < 20; i += 1 {
		// append to a spool
		message := make([]byte, common.SpoolPayloadLength)
		rand.Reader.Read(message[:])
		appendCmd, err := common.AppendToSpool(spoolReadDescriptor.ID, message[:])
		require.NoError(err)
		rawResponse, err := s.BlockingSendReliableMessage(desc.Name, desc.Provider, appendCmd)
		require.NoError(err)
		response, err := common.SpoolResponseFromBytes(rawResponse)
		require.NoError(err)
		require.True(response.IsOK())

		// read from a spool (should find our original message)
		readCmd, err := common.ReadFromSpool(spoolReadDescriptor.ID, messageID, spoolReadDescriptor.PrivateKey)
		require.NoError(err)
		rawResponse, err = s.BlockingSendReliableMessage(desc.Name, desc.Provider, readCmd)
		require.NoError(err)
		response, err = common.SpoolResponseFromBytes(rawResponse)
		require.NoError(err)
		require.True(response.IsOK())
		// XXX require.Equal(response.SpoolID, spoolReadDescriptor.ID)
		require.True(bytes.Equal(response.Message, message[:]))
		messageID += 1
	}
}
