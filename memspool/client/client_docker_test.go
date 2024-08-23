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

//go:build docker_test
// +build docker_test

package client

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/client2"
	"github.com/katzenpost/katzenpost/client2/config"
	"github.com/katzenpost/katzenpost/client2/thin"
	"github.com/katzenpost/katzenpost/memspool/common"
	"github.com/stretchr/testify/require"
)

func TestAllDockerMemspoolClientTests(t *testing.T) {
	d := setupDaemon()

	t.Cleanup(func() {
		d.Shutdown()
	})

	t.Run("TestDockerReliableSpoolService", testDockerReliableSpoolService)
	t.Run("TestDockerGetSpoolServices", testDockerGetSpoolServices)
}

func setupDaemon() *client2.Daemon {
	cfg, err := config.LoadFile("testdata/client.toml")
	if err != nil {
		panic(err)
	}

	d, err := client2.NewDaemon(cfg)
	if err != nil {
		panic(err)
	}
	err = d.Start()
	if err != nil {
		panic(err)
	}

	// maybe we need to sleep first to ensure the daemon is listening first before dialing
	time.Sleep(time.Second * 3)

	return d
}

func testDockerReliableSpoolService(t *testing.T) {
	t.Parallel()

	require := require.New(t)

	cfg, err := config.LoadFile("testdata/client.toml")
	require.NoError(err)

	s := thin.NewThinClient(cfg)
	err = s.Dial()
	require.NoError(err)

	// look up a spool provider
	desc, err := s.GetService(common.SpoolServiceName)
	require.NoError(err)
	t.Logf("Found spool provider: %v@%s", desc.RecipientQueueID, desc.MixDescriptor.Name)

	// create the spool on the remote provider
	providerKey := desc.MixDescriptor.IdentityKey.Sum256()
	spoolReadDescriptor, err := NewSpoolReadDescriptor(desc.RecipientQueueID, &providerKey, s)
	require.NoError(err)

	// append to a spool
	message := []byte("hello there")
	appendCmd, err := common.AppendToSpool(spoolReadDescriptor.ID, message, cfg.SphinxGeometry)
	require.NoError(err)
	mesgID := s.NewMessageID()
	providerKey = desc.MixDescriptor.IdentityKey.Sum256()
	rawResponse, err := s.BlockingSendReliableMessage(mesgID, appendCmd, &providerKey, desc.RecipientQueueID)
	require.NoError(err)
	response := new(common.SpoolResponse)
	err = response.Unmarshal(rawResponse)
	require.NoError(err)
	require.True(response.IsOK())

	messageID := uint32(1) // where do we learn messageID?

	// read from a spool (should find our original message)
	readCmd, err := common.ReadFromSpool(spoolReadDescriptor.ID, messageID, spoolReadDescriptor.PrivateKey)
	require.NoError(err)

	mesgID = s.NewMessageID()
	providerKey = desc.MixDescriptor.IdentityKey.Sum256()
	rawResponse, err = s.BlockingSendReliableMessage(mesgID, readCmd, &providerKey, desc.RecipientQueueID)
	require.NoError(err)
	response = new(common.SpoolResponse)
	err = response.Unmarshal(rawResponse)
	require.NoError(err)
	require.True(response.IsOK())
	// XXX require.Equal(response.SpoolID, spoolReadDescriptor.ID)
	require.True(bytes.Equal(response.Message, message))

	// purge a spool
	purgeCmd, err := common.PurgeSpool(spoolReadDescriptor.ID, spoolReadDescriptor.PrivateKey)
	require.NoError(err)
	providerKey = desc.MixDescriptor.IdentityKey.Sum256()
	mesgID = s.NewMessageID()
	rawResponse, err = s.BlockingSendReliableMessage(mesgID, purgeCmd, &providerKey, desc.RecipientQueueID)
	require.NoError(err)
	response = new(common.SpoolResponse)
	err = response.Unmarshal(rawResponse)
	require.NoError(err)
	t.Logf("status %s", response.StatusAsError())
	require.True(response.IsOK())

	// read from a spool (should be empty?)
	readCmd, err = common.ReadFromSpool(spoolReadDescriptor.ID, messageID, spoolReadDescriptor.PrivateKey)
	require.NoError(err)

	mesgID = s.NewMessageID()
	rawResponse, err = s.BlockingSendReliableMessage(mesgID, readCmd, &providerKey, desc.RecipientQueueID)
	require.NoError(err)
	response = new(common.SpoolResponse)
	err = response.Unmarshal(rawResponse)
	require.NoError(err)
	require.False(response.IsOK())

	err = s.Close()
	require.NoError(err)
}

func testDockerGetSpoolServices(t *testing.T) {
	t.Parallel()

	cfg, err := config.LoadFile("testdata/client.toml")
	require.NoError(err)

	client, err := cc.New(cfg)
	require.NoError(err)

	s, err := client.NewTOFUSession(context.Background())
	require.NoError(err)

	s.WaitForDocument(context.Background())

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
		message := make([]byte, common.SpoolPayloadLength(s.SphinxGeometry()))
		rand.Reader.Read(message[:])
		appendCmd, err := common.AppendToSpool(spoolReadDescriptor.ID, message[:], s.SphinxGeometry())
		require.NoError(err)
		rawResponse, err := s.BlockingSendUnreliableMessage(desc.Name, desc.Provider, appendCmd)
		require.NoError(err)
		response := new(common.SpoolResponse)
		err = response.Unmarshal(rawResponse)
		require.NoError(err)
		require.True(response.IsOK())

		// read from a spool (should find our original message)
		readCmd, err := common.ReadFromSpool(spoolReadDescriptor.ID, messageID, spoolReadDescriptor.PrivateKey)
		require.NoError(err)
		rawResponse, err = s.BlockingSendReliableMessage(desc.Name, desc.Provider, readCmd)
		require.NoError(err)
		response = new(common.SpoolResponse)
		err = response.Unmarshal(rawResponse)
		require.NoError(err)
		require.True(response.IsOK())
		// XXX require.Equal(response.SpoolID, spoolReadDescriptor.ID)
		require.True(bytes.Equal(response.Message, message[:]))
		messageID += 1
	}
}

func TestDockerGetSpoolServices(t *testing.T) {
	require := require.New(t)

	cfg, err := config.LoadFile("testdata/client.toml")
	require.NoError(err)

	s := thin.NewThinClient(cfg)
	err = s.Dial()
	require.NoError(err)

	s, err := client.NewTOFUSession(context.Background())
	require.NoError(err)

	s.WaitForDocument(context.Background())

	spoolServices, err := s.GetServices(common.SpoolServiceName)
	require.NoError(err)

	for _, svc := range spoolServices {
		t.Logf("Got %s ServiceDescriptor: %v", common.SpoolServiceName, svc)
		providerKey := svc.MixDescriptor.IdentityKey.Sum256()

		rd, err := NewSpoolReadDescriptor(svc.RecipientQueueID, &providerKey, s)
		require.NoError(err)
		t.Logf("Got SpoolReadDescriptor: %v", rd)
	}

}
