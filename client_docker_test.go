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
	"github.com/katzenpost/client/session"
	"github.com/katzenpost/core/utils"
	"github.com/stretchr/testify/require"
)

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

	eventRaw := <-clientSession.EventSink
	event1 := eventRaw.(*session.MessageSentEvent)
	require.Equal(msgID[:], event1.MessageID[:])
	t.Logf("received event: %s", event1)

	eventRaw = <-clientSession.EventSink
	event2 := eventRaw.(*session.MessageReplyEvent)
	t.Logf("received event: %s", event2)
	require.Equal(msgID[:], event2.MessageID[:])
	require.True(utils.CtIsZero(event2.Payload))
	require.NoError(event2.Err)
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
			case *session.MessageSentEvent:
				if bytes.Equal(msgID[:], event.MessageID[:]) {
					require.NoError(event.Err)
					wg.Done()
				}
			case *session.MessageReplyEvent:
				if bytes.Equal(msgID[:], event.MessageID[:]) {
					require.NoError(event.Err)
					require.True(utils.CtIsZero(event.Payload))
					wg.Done()
					return
				}
			}
		}
	}()
	wg.Wait()
}
