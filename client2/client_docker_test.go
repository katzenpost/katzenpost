//go:build docker_test

// SPDX-FileCopyrightText: © 2023 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client2

import (
	"context"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/katzenpost/client2/config"
	"github.com/katzenpost/katzenpost/client2/thin"
	cpki "github.com/katzenpost/katzenpost/core/pki"

	"net/http"
	_ "net/http/pprof"
)

var (
	shutdownCh chan interface{}
)

func TestAllClient2Tests(t *testing.T) {
	d, err := setupDaemon()
	require.NoError(t, err)

	t.Cleanup(func() {
		d.Shutdown()
	})

	haltCh := make(chan os.Signal, 1)
	signal.Notify(haltCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-haltCh
		close(shutdownCh)
		t.Log("Interrupt caught. Shutdown")
		d.Shutdown()
	}()

	t.Run("TestDockerMultiplexClients", testDockerMultiplexClients)
	t.Run("TestDockerClientARQSendReceive", testDockerClientARQSendReceive)
	t.Run("TestDockerClientSendReceive", testDockerClientSendReceive)
}

func setupDaemon() (*Daemon, error) {
	cfg, err := config.LoadFile("testdata/client.toml")
	if err != nil {
		return nil, err
	}

	d, err := NewDaemon(cfg)
	if err != nil {
		return nil, err
	}
	err = d.Start()
	if err != nil {
		return nil, err
	}

	// maybe we need to sleep first to ensure the daemon is listening first before dialing
	time.Sleep(time.Second * 3)

	return d, nil
}

func sendAndWait(t *testing.T, client *thin.ThinClient, message []byte, nodeID *[32]byte, queueID []byte) []byte {
	surbID := client.NewSURBID()
	eventSink := client.EventSink()
	err := client.SendMessage(surbID, message, nodeID, queueID)
	require.NoError(t, err)

	for {
		var event thin.Event
		select {
		case event = <-eventSink:
		case <-shutdownCh: // exit if halted
			// interrupt caught, shutdown client
			t.Log("Interrupt caught - shutting down client")
			client.Halt()
			return nil
		}

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
		default:
			panic("impossible event type")
		}
	}
	panic("impossible event type")
}

func testDockerMultiplexClients(t *testing.T) {
	t.Parallel()

	cfg, err := config.LoadFile("testdata/thinclient.toml")
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
	for i := 0; i < len(doc.ServiceNodes); i++ {
		_, ok := doc.ServiceNodes[i].Kaetzchen["echo"]
		if ok {
			pingTargets = append(pingTargets, doc.ServiceNodes[i])
		}
	}
	require.True(t, len(pingTargets) > 0)
	message1 := []byte("hello alice, this is bob.")
	nodeIdKey := hash.Sum256(pingTargets[0].IdentityKey)

	reply := sendAndWait(t, thin1, message1, &nodeIdKey, []byte("+echo"))
	require.Equal(t, message1, reply[:len(message1)])

	reply = sendAndWait(t, thin2, message1, &nodeIdKey, []byte("+echo"))
	require.Equal(t, message1, reply[:len(message1)])

	err = thin1.Close()
	require.NoError(t, err)

	err = thin2.Close()
	require.NoError(t, err)
}

func testDockerClientARQSendReceive(t *testing.T) {
	t.Parallel()

	cfg, err := config.LoadFile("testdata/thinclient.toml")
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
	for i := 0; i < len(doc.ServiceNodes); i++ {
		_, ok := doc.ServiceNodes[i].Kaetzchen["echo"]
		if ok {
			pingTargets = append(pingTargets, doc.ServiceNodes[i])
		}
	}
	require.True(t, len(pingTargets) > 0)
	message1 := []byte("hello alice, this is bob.")
	nodeIdKey := hash.Sum256(pingTargets[0].IdentityKey)

	id1 := thin.NewMessageID()
	id2 := thin.NewMessageID()
	id3 := thin.NewMessageID()
	id4 := thin.NewMessageID()

	message3, err := thin.BlockingSendReliableMessage(context.Background(), id1, message1, &nodeIdKey, []byte("+echo"))
	require.NoError(t, err)
	require.NotEqual(t, message3, []byte{})
	require.Equal(t, message1, message3[:len(message1)])

	message3, err = thin.BlockingSendReliableMessage(context.Background(), id2, message1, &nodeIdKey, []byte("+echo"))
	require.NoError(t, err)
	require.NotEqual(t, message3, []byte{})
	require.Equal(t, message1, message3[:len(message1)])

	message3, err = thin.BlockingSendReliableMessage(context.Background(), id3, message1, &nodeIdKey, []byte("+echo"))
	require.NoError(t, err)
	require.NotEqual(t, message3, []byte{})
	require.Equal(t, message1, message3[:len(message1)])

	message3, err = thin.BlockingSendReliableMessage(context.Background(), id4, message1, &nodeIdKey, []byte("+echo"))
	require.NoError(t, err)
	require.NotEqual(t, message3, []byte{})
	require.Equal(t, message1, message3[:len(message1)])

	message3, err = thin.BlockingSendReliableMessage(context.Background(), id4, message1, &nodeIdKey, []byte("+echo"))
	require.NoError(t, err)
	require.NotEqual(t, message3, []byte{})
	require.Equal(t, message1, message3[:len(message1)])

	message3, err = thin.BlockingSendReliableMessage(context.Background(), id4, message1, &nodeIdKey, []byte("+echo"))
	require.NoError(t, err)
	require.NotEqual(t, message3, []byte{})
	require.Equal(t, message1, message3[:len(message1)])

	message3, err = thin.BlockingSendReliableMessage(context.Background(), id4, message1, &nodeIdKey, []byte("+echo"))
	require.NoError(t, err)
	require.NotEqual(t, message3, []byte{})
	require.Equal(t, message1, message3[:len(message1)])

	err = thin.Close()
	require.NoError(t, err)
}

func testDockerClientSendReceive(t *testing.T) {
	t.Parallel()

	cfg, err := config.LoadFile("testdata/thinclient.toml")
	require.NoError(t, err)

	thin := thin.NewThinClient(cfg)
	t.Log("------------------------------ thin client Dialing")
	err = thin.Dial()
	require.NoError(t, err)
	require.Nil(t, err)
	t.Log("------------------------------ thin client connected")

	t.Log("thin client getting PKI doc")
	doc := thin.PKIDocument()
	require.NotNil(t, doc)
	require.NotEqual(t, doc.LambdaP, 0.0)

	pingTargets := []*cpki.MixDescriptor{}
	for i := 0; i < len(doc.ServiceNodes); i++ {

		for k, _ := range doc.ServiceNodes[i].Kaetzchen {
			t.Logf("Key %s", k)
		}

		_, ok := doc.ServiceNodes[i].Kaetzchen["echo"]
		if ok {
			pingTargets = append(pingTargets, doc.ServiceNodes[i])
		}
	}
	require.True(t, len(pingTargets) > 0)
	message1 := []byte("hello alice, this is bob.")
	nodeIdKey := hash.Sum256(pingTargets[0].IdentityKey)

	t.Log("BEFORE sendAndWait")
	reply := sendAndWait(t, thin, message1, &nodeIdKey, []byte("+testdest"))
	t.Log("AFTER sendAndWait")
	require.Equal(t, message1, reply[:len(message1)])

	reply = sendAndWait(t, thin, message1, &nodeIdKey, []byte("+testdest"))
	require.Equal(t, message1, reply[:len(message1)])

	reply = sendAndWait(t, thin, message1, &nodeIdKey, []byte("+testdest"))
	require.Equal(t, message1, reply[:len(message1)])

	reply = sendAndWait(t, thin, message1, &nodeIdKey, []byte("+testdest"))
	require.Equal(t, message1, reply[:len(message1)])

	reply = sendAndWait(t, thin, message1, &nodeIdKey, []byte("+testdest"))
	require.Equal(t, message1, reply[:len(message1)])

	reply = sendAndWait(t, thin, message1, &nodeIdKey, []byte("+testdest"))
	require.Equal(t, message1, reply[:len(message1)])

	err = thin.Close()
	require.NoError(t, err)
}

func init() {
	shutdownCh = make(chan interface{})
	go func() {
		http.ListenAndServe("localhost:4242", nil)
	}()
	runtime.SetMutexProfileFraction(1)
	runtime.SetBlockProfileRate(1)
}
