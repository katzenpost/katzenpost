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

//go:build docker_test
// +build docker_test

package client

import (
	"bytes"
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/client/constants"
	"github.com/katzenpost/katzenpost/core/epochtime"
	sConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/stretchr/testify/require"
)

func TestDockerClientConnectShutdown(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	cfg, err := config.LoadFile("testdata/client.toml")
	require.NoError(err)

	client, err := New(cfg)
	require.NoError(err)

	session, err := client.NewTOFUSession(context.Background())
	require.NoError(err)

	<-session.EventSink

	client.Shutdown()
	client.Wait()
}

func TestDockerClientAsyncSendReceive(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	cfg, err := config.LoadFile("testdata/client.toml")
	require.NoError(err)

	client, err := New(cfg)
	require.NoError(err)

	ctx := context.Background()
	clientSession, err := client.NewTOFUSession(ctx)
	require.NoError(err)

	clientSession.WaitForDocument(ctx)
	desc, err := clientSession.GetService(constants.LoopService)
	require.NoError(err)

	msgID, err := clientSession.SendReliableMessage(desc.Name, desc.Provider, []byte("hello"))
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
					require.True(bytes.Equal([]byte("hello"), event.Payload[:5])) // padding
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
	t.Parallel()
	require := require.New(t)

	cfg, err := config.LoadFile("testdata/client.toml")
	require.NoError(err)

	cfg.Debug.DisableDecoyTraffic = false
	client, err := New(cfg)
	require.NoError(err)

	ctx := context.Background()
	clientSession, err := client.NewTOFUSession(ctx)
	require.NoError(err)

	clientSession.WaitForDocument(ctx)
	desc, err := clientSession.GetService(constants.LoopService)
	require.NoError(err)

	msgID, err := clientSession.SendReliableMessage(desc.Name, desc.Provider, []byte("hello"))
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
					require.True(bytes.Equal([]byte("hello"), event.Payload[:5])) // padding
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

func TestDockerClientTestGarbageCollection(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	cfg, err := config.LoadFile("testdata/client.toml")
	require.NoError(err)

	client, err := New(cfg)
	require.NoError(err)

	clientSession, err := client.NewTOFUSession(context.Background())
	require.NoError(err)

	msgID := [constants.MessageIDLength]byte{}
	_, err = io.ReadFull(rand.Reader, msgID[:])
	var msg = Message{
		ID:         &msgID,
		IsBlocking: false,
		SentAt:     time.Now().AddDate(0, 0, -1),
		ReplyETA:   10 * time.Second,
	}
	// actually the key should be a SURB ID, but this works fine for the test
	clientSession.surbIDMap.Store(msgID, &msg)
	clientSession.garbageCollect()
	_, ok := clientSession.surbIDMap.Load(msgID)
	require.False(ok)

	client.Shutdown()
	client.Wait()
}

func TestDockerClientTestIntegrationGarbageCollection(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	cfg, err := config.LoadFile("testdata/client.toml")
	require.NoError(err)

	client, err := New(cfg)
	require.NoError(err)

	ctx := context.Background()
	clientSession, err := client.NewTOFUSession(ctx)
	require.NoError(err)

	clientSession.WaitForDocument(ctx)
	desc, err := clientSession.GetService(constants.LoopService)
	require.NoError(err)

	// Send a message to a nonexistent service so that we don't get a reply and thus
	// retain an entry in the SURB ID Map which we must garbage collect.
	msgID, err := clientSession.SendUnreliableMessage("nonexistent", desc.Provider, []byte("hello"))
	require.NoError(err)
	t.Logf("sent message ID %x", msgID)

	var surbID [sConstants.SURBIDLength]byte
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		for eventRaw := range clientSession.EventSink {
			switch event := eventRaw.(type) {
			case *MessageSentEvent:
				if bytes.Equal(msgID[:], event.MessageID[:]) {
					require.NoError(event.Err)
					surbIDMapRange := func(rawSurbID, rawMessage interface{}) bool {
						surbID = rawSurbID.([sConstants.SURBIDLength]byte)
						return true
					}
					clientSession.surbIDMap.Range(surbIDMapRange)
					_, _, till := epochtime.Now()
					duration := time.Duration(till + 1 * epochtime.Period)
					t.Logf("Sleeping for %s so that the SURB ID Map entry will get garbage collected.", duration)
					time.Sleep(duration)
					wg.Done()
					return
				}
			default:
				continue
			}
		}
	}()
	wg.Wait()

	clientSession.garbageCollect()
	_, ok := clientSession.surbIDMap.Load(surbID)
	require.False(ok)

	client.Shutdown()
	client.Wait()
}
