//go:build docker_test

// SPDX-FileCopyrightText: Copyright (C) 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client2

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/client2/config"
	"github.com/katzenpost/katzenpost/client2/thin"
	cpki "github.com/katzenpost/katzenpost/core/pki"
)

const (
	defaultThinClientConfigFile = "testdata/thinclient.toml"
	defaultTestLogLevel         = "DEBUG"
)

var (
	shutdownCh chan interface{}
)

// setupThinClientWithConfig creates and connects a thin client with the specified configuration
func setupThinClientWithConfig(t *testing.T, configFile, logLevel string) *thin.ThinClient {
	cfg, err := thin.LoadFile(configFile)
	require.NoError(t, err)

	logging := &config.Logging{
		Disable: false,
		File:    "",
		Level:   logLevel,
	}

	client := thin.NewThinClient(cfg, logging)
	t.Log("thin client Dialing")
	err = client.Dial()
	require.NoError(t, err)
	t.Log("thin client connected")

	return client
}

// setupThinClient creates and connects a thin client with default test configuration
func setupThinClient(t *testing.T) *thin.ThinClient {
	return setupThinClientWithConfig(t, defaultThinClientConfigFile, defaultTestLogLevel)
}

// validatePKIDocument gets and validates the PKI document from a thin client
func validatePKIDocument(t *testing.T, client *thin.ThinClient) *cpki.Document {
	t.Log("thin client getting PKI doc")
	doc := client.PKIDocument()
	require.NotNil(t, doc)
	require.NotEqual(t, doc.LambdaP, 0.0)
	return doc
}

// validatePKIDocumentForEpoch gets and validates the PKI document for a specific epoch from a thin client
func validatePKIDocumentForEpoch(t *testing.T, client *thin.ThinClient, epoch uint64) *cpki.Document {
	t.Logf("thin client getting PKI doc for epoch %d", epoch)
	doc, err := client.PKIDocumentForEpoch(epoch)
	require.NoError(t, err)
	require.NotNil(t, doc)
	require.Equal(t, epoch, doc.Epoch)
	require.NotEqual(t, doc.LambdaP, 0.0)
	return doc
}

// findEchoTargets finds service nodes that support the echo service
func findEchoTargets(t *testing.T, doc *cpki.Document) []*cpki.MixDescriptor {
	pingTargets := []*cpki.MixDescriptor{}
	for i := 0; i < len(doc.ServiceNodes); i++ {
		_, ok := doc.ServiceNodes[i].Kaetzchen["echo"]
		if ok {
			pingTargets = append(pingTargets, doc.ServiceNodes[i])
		}
	}
	require.True(t, len(pingTargets) > 0)
	return pingTargets
}

// setupClientAndTargets sets up a thin client and finds echo targets - common test setup pattern
func setupClientAndTargets(t *testing.T) (*thin.ThinClient, []*cpki.MixDescriptor) {
	client := setupThinClient(t)
	doc := validatePKIDocument(t, client)
	targets := findEchoTargets(t, doc)
	return client, targets
}

// sendAndWait sends a message and waits for a reply
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

// repeatSendAndWait sends the same message multiple times using sendAndWait
func repeatSendAndWait(t *testing.T, client *thin.ThinClient, message []byte, nodeID *[32]byte, queueID []byte, count int) {
	for i := 0; i < count; i++ {
		reply := sendAndWait(t, client, message, nodeID, queueID)
		require.Equal(t, message, reply[:len(message)])
	}
}

// repeatBlockingSendReliableMessage sends the same message multiple times using BlockingSendReliableMessage
func repeatBlockingSendReliableMessage(t *testing.T, client *thin.ThinClient, message []byte, nodeID *[32]byte, queueID []byte, count int) {
	for i := 0; i < count; i++ {
		messageID := client.NewMessageID()
		reply, err := client.BlockingSendReliableMessage(context.Background(), messageID, message, nodeID, queueID)
		require.NoError(t, err)
		require.NotEqual(t, reply, []byte{})
		require.Equal(t, message, reply[:len(message)])
	}
}

func init() {
	shutdownCh = make(chan interface{})
}
