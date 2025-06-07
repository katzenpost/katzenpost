//go:build docker_test

// SPDX-FileCopyrightText: © 2023 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client2

import (
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/katzenpost/client2/thin"

	"net/http"
	_ "net/http/pprof"
)

var (
	shutdownCh chan interface{}
)

func TestAllClient2Tests(t *testing.T) {
	// Setup signal handling for graceful shutdown
	haltCh := make(chan os.Signal, 1)
	signal.Notify(haltCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-haltCh
		close(shutdownCh)
		t.Log("Interrupt caught. Shutdown")
	}()

	t.Run("TestDockerMultiplexClients", testDockerMultiplexClients)
	t.Run("TestDockerClientARQSendReceive", testDockerClientARQSendReceive)
	t.Run("TestDockerClientSendReceive", testDockerClientSendReceive)
	t.Run("TestDockerCourierService", testDockerCourierService)
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

	client1, pingTargets := setupClientAndTargets(t)
	defer client1.Close()

	client2 := setupThinClient(t)
	defer client2.Close()

	message1 := []byte("hello alice, this is bob.")
	nodeIdKey := hash.Sum256(pingTargets[0].IdentityKey)

	reply := sendAndWait(t, client1, message1, &nodeIdKey, []byte("+echo"))
	require.Equal(t, message1, reply[:len(message1)])

	reply = sendAndWait(t, client2, message1, &nodeIdKey, []byte("+echo"))
	require.Equal(t, message1, reply[:len(message1)])
}

func testDockerClientARQSendReceive(t *testing.T) {
	t.Parallel()

	client, pingTargets := setupClientAndTargets(t)
	defer client.Close()

	message1 := []byte("hello alice, this is bob.")
	nodeIdKey := hash.Sum256(pingTargets[0].IdentityKey)

	// Send the same message 7 times using BlockingSendReliableMessage
	repeatBlockingSendReliableMessage(t, client, message1, &nodeIdKey, []byte("+echo"), 7)
}

func testDockerClientSendReceive(t *testing.T) {
	t.Parallel()

	client, pingTargets := setupClientAndTargets(t)
	defer client.Close()

	message1 := []byte("hello alice, this is bob.")
	nodeIdKey := hash.Sum256(pingTargets[0].IdentityKey)

	t.Log("BEFORE sendAndWait")
	reply := sendAndWait(t, client, message1, &nodeIdKey, []byte("+testdest"))
	t.Log("AFTER sendAndWait")
	require.Equal(t, message1, reply[:len(message1)])

	// Send the same message 5 more times
	repeatSendAndWait(t, client, message1, &nodeIdKey, []byte("+testdest"), 5)
}

func init() {
	shutdownCh = make(chan interface{})
	go func() {
		http.ListenAndServe("localhost:4242", nil)
	}()
	runtime.SetMutexProfileFraction(1)
	runtime.SetBlockProfileRate(1)
}
