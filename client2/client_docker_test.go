//go:build docker_test

// SPDX-FileCopyrightText: © 2023 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client2

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/client2/config"
	cpki "github.com/katzenpost/katzenpost/core/pki"
)

func TestAllClient2Tests(t *testing.T) {
	d := setupDaemon()

	t.Cleanup(func() {
		d.Shutdown()
	})

	//t.Run("TestDockerMultiplexClients", testDockerMultiplexClients)
	t.Run("TestDockerClientARQSendReceive", testDockerClientARQSendReceive)
}

func setupDaemon() *Daemon {
	cfg, err := config.LoadFile("testdata/client.toml")
	if err != nil {
		panic(err)
	}

	egressSize := 1000
	d, err := NewDaemon(cfg, egressSize)
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

func testDockerMultiplexClients(t *testing.T) {
	t.Parallel()

	// daemon listen

	cfg, err := config.LoadFile("testdata/client.toml")
	require.NoError(t, err)

	// client 1 dial

	thin1 := NewThinClient(cfg)
	t.Log("thin client Dialing")
	err = thin1.Dial()
	require.NoError(t, err)
	require.Nil(t, err)
	t.Log("thin client connected")

	// client 2 dial

	thin2 := NewThinClient(cfg)
	t.Log("thin client Dialing")
	err = thin2.Dial()
	require.NoError(t, err)
	require.Nil(t, err)
	t.Log("thin client connected")

	// client 1 prepare to send

	t.Log("thin client getting PKI doc")
	doc := thin1.PKIDocument()
	require.NotNil(t, doc)
	require.NotEqual(t, doc.LambdaP, 0.0)

	pingTargets := []*cpki.MixDescriptor{}
	for i := 0; i < len(doc.Providers); i++ {
		_, ok := doc.Providers[i].Kaetzchen["testdest"]
		if ok {
			pingTargets = append(pingTargets, doc.Providers[i])
		}
	}
	require.True(t, len(pingTargets) > 0)
	message1 := []byte("hello alice, this is bob.")
	nodeIdKey := pingTargets[0].IdentityKey.Sum256()

	// client 1 send/receive

	t.Log("thin client send ping")
	surbID := thin1.NewSURBID()
	err = thin1.SendMessage(surbID, message1, &nodeIdKey, []byte("testdest"))
	require.NoError(t, err)

	eventSink := thin1.EventSink()
	message2 := []byte{}

Loop:
	for {
		event := <-eventSink
		switch v := event.(type) {
		case *ConnectionStatusEvent:
			t.Log("ConnectionStatusEvent")
			if !v.IsConnected {
				panic("socket connection lost")
			}
		case *NewDocumentEvent:
			t.Log("NewPKIDocumentEvent")
		case *MessageSentEvent:
			t.Log("MessageSentEvent")
		case *MessageReplyEvent:
			t.Log("MessageReplyEvent")
			require.Equal(t, surbID[:], v.SURBID[:])
			message2 = v.Payload
			break Loop
		default:
			panic("impossible event type")
		}
	}

	require.NotEqual(t, message1, []byte{})
	require.NotEqual(t, message2, []byte{})
	require.Equal(t, message1, message2[:len(message1)])
}

func testDockerClientARQSendReceive(t *testing.T) {
	t.Parallel()

	cfg, err := config.LoadFile("testdata/client.toml")
	require.NoError(t, err)

	thin := NewThinClient(cfg)
	t.Log("thin client Dialing")
	err = thin.Dial()
	require.NoError(t, err)
	require.Nil(t, err)
	t.Log("thin client connected")

	t.Log("thin client getting PKI doc")
	doc := thin.PKIDocument()
	require.NotNil(t, doc)
	require.NotEqual(t, doc.LambdaP, 0.0)

	pingTargets := []*cpki.MixDescriptor{}
	for i := 0; i < len(doc.Providers); i++ {
		_, ok := doc.Providers[i].Kaetzchen["testdest"]
		if ok {
			pingTargets = append(pingTargets, doc.Providers[i])
		}
	}
	require.True(t, len(pingTargets) > 0)
	message1 := []byte("hello alice, this is bob.")
	nodeIdKey := pingTargets[0].IdentityKey.Sum256()

	// Test ARQ send/receive

	/*
			id := &[MessageIDLength]byte{}
			_, err = rand.Reader.Read(id[:])
			require.NoError(t, err)

			err = thin.SendReliableMessage(id, message1, &nodeIdKey, []byte("testdest"))
			require.NoError(t, err)

			eventSink := thin.EventSink()
			message2 := []byte{}

		Loop:
			for {
				event := <-eventSink
				switch v := event.(type) {
				case *ConnectionStatusEvent:
					t.Log("ConnectionStatusEvent")
					if !v.IsConnected {
						panic("socket connection lost")
					}
				case *NewDocumentEvent:
					t.Log("NewPKIDocumentEvent")
				case *MessageSentEvent:
					t.Log("MessageSentEvent")
				case *MessageReplyEvent:
					t.Log("MessageReplyEvent")
					require.Equal(t, id[:], v.MessageID[:])
					message2 = v.Payload
					break Loop
				default:
					panic("impossible event type")
				}
			}

			require.NotEqual(t, message1, []byte{})
			require.NotEqual(t, message2, []byte{})
			require.Equal(t, message1, message2[:len(message1)])
	*/
	id1 := thin.NewMessageID()
	id2 := thin.NewMessageID()
	id3 := thin.NewMessageID()
	id4 := thin.NewMessageID()

	message3, err := thin.BlockingSendReliableMessage(id1, message1, &nodeIdKey, []byte("testdest"))
	require.NoError(t, err)
	require.NotEqual(t, message3, []byte{})
	require.Equal(t, message1, message3[:len(message1)])

	message3, err = thin.BlockingSendReliableMessage(id2, message1, &nodeIdKey, []byte("testdest"))
	require.NoError(t, err)
	require.NotEqual(t, message3, []byte{})
	require.Equal(t, message1, message3[:len(message1)])

	message3, err = thin.BlockingSendReliableMessage(id3, message1, &nodeIdKey, []byte("testdest"))
	require.NoError(t, err)
	require.NotEqual(t, message3, []byte{})
	require.Equal(t, message1, message3[:len(message1)])

	message3, err = thin.BlockingSendReliableMessage(id4, message1, &nodeIdKey, []byte("testdest"))
	require.NoError(t, err)
	require.NotEqual(t, message3, []byte{})
	require.Equal(t, message1, message3[:len(message1)])

	err = thin.Close()
	require.NoError(t, err)
}
