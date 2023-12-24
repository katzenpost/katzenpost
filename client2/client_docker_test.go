//go:build docker_test

// SPDX-FileCopyrightText: © 2023 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client2

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/client2/config"
	"github.com/katzenpost/katzenpost/core/crypto/rand"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	sConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
)

func TestDockerClientShutdown(t *testing.T) {
	cfg, err := config.LoadFile("testdata/client.toml")
	require.NoError(t, err)

	egressSize := 100
	d, err := NewDaemon(cfg, egressSize)
	require.NoError(t, err)
	err = d.Start()
	require.NoError(t, err)

	time.Sleep(time.Second * 3)

	d.Halt()
}

func TestDockerClientSendReceive(t *testing.T) {
	cfg, err := config.LoadFile("testdata/client.toml")
	require.NoError(t, err)

	egressSize := 100
	d, err := NewDaemon(cfg, egressSize)
	require.NoError(t, err)
	err = d.Start()
	require.NoError(t, err)

	time.Sleep(time.Second * 3)

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

	// Test send/receive

	t.Log("thin client send ping")
	surbID := &[sConstants.SURBIDLength]byte{}
	_, err = rand.Reader.Read(surbID[:])
	require.NoError(t, err)

	thin.SendMessage(surbID, message1, &nodeIdKey, []byte("testdest"))

	time.Sleep(time.Second * 3)

	replyID, message2 := thin.ReceiveMessage()

	require.NoError(t, err)
	require.NotEqual(t, message1, []byte{})
	require.NotEqual(t, message2, []byte{})
	require.Equal(t, message1, message2[:len(message1)])
	require.Equal(t, replyID, surbID)

	// Test ARQ send/receive

	id := &[MessageIDLength]byte{}
	_, err = rand.Reader.Read(id[:])
	require.NoError(t, err)

	thin.ARQSend(id, message1, &nodeIdKey, []byte("testdest"))
	time.Sleep(time.Second * 3)

	replyID, message2 = thin.ARQReceiveMessage()

	require.NotNil(t, replyID)
	require.NoError(t, err)
	require.NotEqual(t, message1, []byte{})
	require.NotEqual(t, message2, []byte{})
	require.Equal(t, message1, message2[:len(message1)])
	require.Equal(t, replyID[:], id[:])

	d.Halt()
}
