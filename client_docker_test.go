// client_docker_test.go - optional client docker test
// Copyright (C) 2019  David Stainton.
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
	"sync"
	"testing"

	"github.com/katzenpost/client/config"
	"github.com/katzenpost/core/utils"
	"github.com/stretchr/testify/require"
)

func TestDockerClientConnectShutdown(t *testing.T) {
	require := require.New(t)

	cfg, err := config.LoadFile("testdata/client.toml")
	require.NoError(err)

	cfg, linkKey := AutoRegisterRandomClient(cfg)
	client, err := New(cfg)
	require.NoError(err)

	session, err := client.NewSession(linkKey)
	require.NoError(err)

	<-session.EventSink

	client.Shutdown()
	client.Wait()
}

func TestDockerClientBlockingSendReceive(t *testing.T) {
	require := require.New(t)

	cfg, err := config.LoadFile("testdata/client.toml")
	require.NoError(err)

	cfg, linkKey := AutoRegisterRandomClient(cfg)
	client, err := New(cfg)
	require.NoError(err)

	session, err := client.NewSession(linkKey)
	require.NoError(err)

	desc, err := session.GetService("loop")
	require.NoError(err)

	reply, err := session.BlockingSendUnreliableMessage(desc.Name, desc.Provider, []byte("hello"))
	require.NoError(err)
	require.True(utils.CtIsZero(reply))

	client.Shutdown()
	client.Wait()
}

func TestDockerClientBlockingSendReceiveWithDecoyTraffic(t *testing.T) {
	require := require.New(t)

	cfg, err := config.LoadFile("testdata/client.toml")
	require.NoError(err)

	cfg, linkKey := AutoRegisterRandomClient(cfg)
	cfg.Debug.DisableDecoyTraffic = false
	client, err := New(cfg)
	require.NoError(err)

	session, err := client.NewSession(linkKey)
	require.NoError(err)

	desc, err := session.GetService("loop")
	require.NoError(err)

	reply, err := session.BlockingSendUnreliableMessage(desc.Name, desc.Provider, []byte("hello"))
	require.NoError(err)
	require.True(utils.CtIsZero(reply))

	client.Shutdown()
	client.Wait()
}

func TestDockerClientAsyncSendReceive(t *testing.T) {
	require := require.New(t)

	cfg, err := config.LoadFile("testdata/client.toml")
	require.NoError(err)

	cfg, linkKey := AutoRegisterRandomClient(cfg)
	client, err := New(cfg)
	require.NoError(err)

	clientSession, err := client.NewSession(linkKey)
	require.NoError(err)

	desc, err := clientSession.GetService("loop")
	require.NoError(err)

	msgID, err := clientSession.SendUnreliableMessage(desc.Name, desc.Provider, []byte("hello"))
	require.NoError(err)
	t.Logf("sent message ID %x", msgID)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		for eventRaw := range clientSession.EventSink {
			switch event := eventRaw.(type) {
			case *MessageSentEvent:
				if bytes.Equal(msgID[:], event.MessageID[:]) {
					require.NoError(event.Err)
					wg.Done()
				}
			case *MessageReplyEvent:
				if bytes.Equal(msgID[:], event.MessageID[:]) {
					require.NoError(event.Err)
					require.True(utils.CtIsZero(event.Payload))
					wg.Done()
					return
				}
			default:
				continue
			}
		}
	}()
	wg.Wait()

	client.Shutdown()
	client.Wait()
}

func TestDockerClientAsyncSendReceiveWithDecoyTraffic(t *testing.T) {
	require := require.New(t)

	cfg, err := config.LoadFile("testdata/client.toml")
	require.NoError(err)

	cfg, linkKey := AutoRegisterRandomClient(cfg)
	cfg.Debug.DisableDecoyTraffic = false
	client, err := New(cfg)
	require.NoError(err)

	clientSession, err := client.NewSession(linkKey)
	require.NoError(err)

	desc, err := clientSession.GetService("loop")
	require.NoError(err)

	msgID, err := clientSession.SendUnreliableMessage(desc.Name, desc.Provider, []byte("hello"))
	require.NoError(err)
	t.Logf("sent message ID %x", msgID)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		for eventRaw := range clientSession.EventSink {
			switch event := eventRaw.(type) {
			case *MessageSentEvent:
				if bytes.Equal(msgID[:], event.MessageID[:]) {
					require.NoError(event.Err)
					wg.Done()
				}
			case *MessageReplyEvent:
				if bytes.Equal(msgID[:], event.MessageID[:]) {
					require.NoError(event.Err)
					require.True(utils.CtIsZero(event.Payload))
					wg.Done()
					return
				}
			default:
				continue
			}
		}
	}()
	wg.Wait()

	client.Shutdown()
	client.Wait()
}
