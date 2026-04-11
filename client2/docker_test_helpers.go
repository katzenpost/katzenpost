//go:build docker_test

// SPDX-FileCopyrightText: Copyright (C) 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client2

import (
	"fmt"
	"testing"
	"time"

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

// sendAndWait sends a message and waits for a reply, returning an error on timeout or failure.
func sendAndWait(t *testing.T, client *thin.ThinClient, message []byte, nodeID *[32]byte, queueID []byte) ([]byte, error) {
	surbID := client.NewSURBID()
	eventSink := client.EventSink()
	err := client.SendMessage(surbID, message, nodeID, queueID)
	if err != nil {
		return nil, fmt.Errorf("SendMessage: %w", err)
	}

	timeout := time.After(1 * time.Minute)
	for {
		var event thin.Event
		select {
		case event = <-eventSink:
		case <-timeout:
			return nil, fmt.Errorf("timed out waiting for reply")
		case <-shutdownCh:
			t.Log("Interrupt caught - shutting down client")
			client.Halt()
			return nil, fmt.Errorf("interrupted")
		}

		switch v := event.(type) {
		case *thin.MessageIDGarbageCollected:
			t.Log("MessageIDGarbageCollected")
		case *thin.ConnectionStatusEvent:
			t.Log("ConnectionStatusEvent")
			if !v.IsConnected {
				return nil, fmt.Errorf("socket connection lost")
			}
		case *thin.NewDocumentEvent:
			t.Log("NewDocumentEvent")
		case *thin.MessageSentEvent:
			t.Log("MessageSentEvent")
		case *thin.MessageReplyEvent:
			t.Log("MessageReplyEvent")
			if fmt.Sprintf("%x", surbID[:]) != fmt.Sprintf("%x", v.SURBID[:]) {
				return nil, fmt.Errorf("SURBID mismatch")
			}
			return v.Payload, nil
		default:
			return nil, fmt.Errorf("unexpected event type: %T", v)
		}
	}
}

// repeatSendAndWait sends the same message multiple times using sendAndWait.
func repeatSendAndWait(t *testing.T, client *thin.ThinClient, message []byte, nodeID *[32]byte, queueID []byte, count int) error {
	for i := 0; i < count; i++ {
		reply, err := sendAndWait(t, client, message, nodeID, queueID)
		if err != nil {
			return err
		}
		if len(reply) < len(message) || string(reply[:len(message)]) != string(message) {
			return fmt.Errorf("reply mismatch on iteration %d", i)
		}
	}
	return nil
}

func init() {
	shutdownCh = make(chan interface{})
}
