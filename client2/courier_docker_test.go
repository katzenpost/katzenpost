//go:build docker_test

// SPDX-FileCopyrightText: Copyright (C) 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client2

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"

	"github.com/katzenpost/katzenpost/client2/config"
	"github.com/katzenpost/katzenpost/client2/thin"
)

func testDockerCourierService(t *testing.T) {
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

	descs, err := thin.GetServices("courier")
	require.NoError(t, err)

	require.NotNil(t, descs)
	require.True(t, len(descs) > 0)

	target := descs[0]

	message1 := []byte("hello alice, this is bob.")
	nodeIdKey := hash.Sum256(target.MixDescriptor.IdentityKey)

	reply := sendAndWait(t, thin, message1, &nodeIdKey, target.RecipientQueueID)
	require.NotNil(t, reply)
}
