//go:build docker_test

// SPDX-FileCopyrightText: © 2023 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client2

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/katzenpost/client2/config"
	"github.com/katzenpost/katzenpost/client2/thin"
	cpki "github.com/katzenpost/katzenpost/core/pki"
)

func TestAllClient2Tests(t *testing.T) {
	d := setupDaemon()

	t.Cleanup(func() {
		d.Shutdown()
	})

	t.Run("TestDockerMultiplexClients", testDockerMultiplexClients)
	t.Run("TestDockerClientARQSendReceive", testDockerClientARQSendReceive)
	t.Run("TestDockerClientSendReceive", testDockerClientSendReceive)
}

func setupDaemon() *Daemon {
	cfg, err := config.LoadFile("testdata/client.toml")
	if err != nil {
		panic(err)
	}

	d, err := NewDaemon(cfg)
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

func sendAndWait(t *testing.T, client *thin.ThinClient, message []byte, nodeID *[32]byte, queueID []byte) []byte {
	surbID := client.NewSURBID()
	err := client.SendMessage(surbID, message, nodeID, queueID)
	require.NoError(t, err)

	eventSink := client.EventSink()
Loop:
	for {
		event := <-eventSink
		switch v := event.(type) {
		case *thin.MessageIDGarbageCollected:
			t.Log("MessageIDGarbageCollected")
		case *thin.ConnectionStatusEvent:
			t.Log("ConnectionStatusEvent")
			if !v.IsConnected {
				panic("socket connection lost")
			}
		case *thin.NewDocumentEvent:
			t.Log("NewPKIDocumentEvent")
		case *thin.MessageSentEvent:
			t.Log("MessageSentEvent")
		case *thin.MessageReplyEvent:
			t.Log("MessageReplyEvent")
			require.Equal(t, surbID[:], v.SURBID[:])
			return v.Payload
			break Loop
		default:
			panic("impossible event type")
		}
	}
	panic("impossible event type")
}

func testDockerMultiplexClients(t *testing.T) {
	t.Parallel()

	cfg, err := config.LoadFile("testdata/client.toml")
	require.NoError(t, err)

	thin1 := thin.NewThinClient(cfg)
	t.Log("thin client Dialing")
	err = thin1.Dial()
	require.NoError(t, err)
	require.Nil(t, err)
	t.Log("thin client connected")

	thin2 := thin.NewThinClient(cfg)
	t.Log("thin client Dialing")
	err = thin2.Dial()
	require.NoError(t, err)
	require.Nil(t, err)
	t.Log("thin client connected")

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
	nodeIdKey := hash.Sum256(pingTargets[0].IdentityKey)

	reply := sendAndWait(t, thin1, message1, &nodeIdKey, []byte("testdest"))
	require.Equal(t, message1, reply[:len(message1)])

	reply = sendAndWait(t, thin2, message1, &nodeIdKey, []byte("testdest"))
	require.Equal(t, message1, reply[:len(message1)])

	err = thin1.Close()
	require.NoError(t, err)

	err = thin2.Close()
	require.NoError(t, err)
}

func testDockerClientARQSendReceive(t *testing.T) {
	t.Parallel()

	cfg, err := config.LoadFile("testdata/client.toml")
	require.NoError(t, err)

	thin := thin.NewThinClient(cfg)
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
	nodeIdKey := hash.Sum256(pingTargets[0].IdentityKey)

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

	message3, err = thin.BlockingSendReliableMessage(id4, message1, &nodeIdKey, []byte("testdest"))
	require.NoError(t, err)
	require.NotEqual(t, message3, []byte{})
	require.Equal(t, message1, message3[:len(message1)])

	message3, err = thin.BlockingSendReliableMessage(id4, message1, &nodeIdKey, []byte("testdest"))
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

func testDockerClientSendReceive(t *testing.T) {
	t.Parallel()

	cfg, err := config.LoadFile("testdata/client.toml")
	require.NoError(t, err)

	thin := thin.NewThinClient(cfg)
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
	nodeIdKey := hash.Sum256(pingTargets[0].IdentityKey)

	reply := sendAndWait(t, thin, message1, &nodeIdKey, []byte("testdest"))
	require.Equal(t, message1, reply[:len(message1)])

	reply = sendAndWait(t, thin, message1, &nodeIdKey, []byte("testdest"))
	require.Equal(t, message1, reply[:len(message1)])

	reply = sendAndWait(t, thin, message1, &nodeIdKey, []byte("testdest"))
	require.Equal(t, message1, reply[:len(message1)])

	reply = sendAndWait(t, thin, message1, &nodeIdKey, []byte("testdest"))
	require.Equal(t, message1, reply[:len(message1)])

	reply = sendAndWait(t, thin, message1, &nodeIdKey, []byte("testdest"))
	require.Equal(t, message1, reply[:len(message1)])

	reply = sendAndWait(t, thin, message1, &nodeIdKey, []byte("testdest"))
	require.Equal(t, message1, reply[:len(message1)])

	err = thin.Close()
	require.NoError(t, err)
}
