//go:build docker_test

// SPDX-FileCopyrightText: Copyright (C) 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client2

import (
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
