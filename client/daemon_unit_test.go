// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package client

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/core/log"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	sphinxConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
)

func TestNewDaemon(t *testing.T) {
	cfg, err := config.LoadFile("testdata/client.toml")
	require.NoError(t, err)

	d, err := NewDaemon(cfg)
	require.NoError(t, err)
	require.NotNil(t, d)
	require.NotNil(t, d.egressCh)
	require.NotNil(t, d.ingressCh)
	require.NotNil(t, d.replies)
	require.NotNil(t, d.decoys)
	require.NotNil(t, d.replyLock)
	require.NotNil(t, d.arqSurbIDMap)
	require.NotNil(t, d.arqResendCh)
	require.NotNil(t, d.arqEnvelopeHashMap)
	require.NotNil(t, d.secureRand)
	require.NotNil(t, d.log)
	require.NotNil(t, d.logbackend)
}

func TestNewDaemonInitLoggingRelativePath(t *testing.T) {
	cfg, err := config.LoadFile("testdata/client.toml")
	require.NoError(t, err)

	// Set a relative path which should fail validation
	cfg.Logging.File = "relative/path.log"

	_, err = NewDaemon(cfg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "absolute path")
}

func TestProxyReplies(t *testing.T) {
	d := &Daemon{
		ingressCh: make(chan *sphinxReply, 10),
	}

	surbID := &[sphinxConstants.SURBIDLength]byte{}
	copy(surbID[:], []byte("test-surb-id-001"))
	ciphertext := []byte("test-ciphertext-data")

	err := d.proxyReplies(surbID, ciphertext)
	require.NoError(t, err)

	// Verify the reply was queued
	select {
	case reply := <-d.ingressCh:
		require.Equal(t, surbID, reply.surbID)
		require.Equal(t, ciphertext, reply.ciphertext)
	case <-time.After(time.Second):
		t.Fatal("expected reply on ingressCh")
	}
}

func TestProxyRepliesHalted(t *testing.T) {
	d := &Daemon{
		ingressCh: make(chan *sphinxReply), // unbuffered, will block
	}
	d.Halt() // signal halt

	surbID := &[sphinxConstants.SURBIDLength]byte{}
	err := d.proxyReplies(surbID, []byte("data"))
	require.NoError(t, err) // returns nil even when halted
}

func TestOnDocument(t *testing.T) {
	cfg, err := config.LoadFile("testdata/client.toml")
	require.NoError(t, err)

	port, err := getFreePort()
	require.NoError(t, err)
	cfg.ListenAddress = fmt.Sprintf("localhost:%d", port)

	d, err := NewDaemon(cfg)
	require.NoError(t, err)

	err = d.Start()
	require.NoError(t, err)

	doc := &cpki.Document{
		LambdaP:         0.005,
		LambdaPMaxDelay: 30000,
		LambdaL:         0.001,
	}

	// Should not panic and should update poll interval
	d.onDocument(doc)

	// Verify poll interval was set (1/(LambdaP+LambdaL) * 0.8)
	expectedInterval := time.Duration((1.0 / (doc.LambdaP + doc.LambdaL)) * 0.8 * float64(time.Millisecond))
	actual := d.client.GetPollInterval()
	require.Equal(t, expectedInterval, actual)

	d.Shutdown()
}

func TestHandleReplyUnknownSURBID(t *testing.T) {
	d := &Daemon{
		replies:      make(map[[sphinxConstants.SURBIDLength]byte]replyDescriptor),
		decoys:       make(map[[sphinxConstants.SURBIDLength]byte]replyDescriptor),
		arqSurbIDMap: make(map[[sphinxConstants.SURBIDLength]byte]*ARQMessage),
		replyLock:    new(sync.Mutex),
	}

	logBackend, err := log.New("", "debug", false)
	require.NoError(t, err)
	d.log = logBackend.GetLogger("test")

	// An unknown SURB ID should be silently dropped (default case in handleReply)
	unknownSurbID := &[sphinxConstants.SURBIDLength]byte{}
	copy(unknownSurbID[:], []byte("unknown-surb-id!"))

	reply := &sphinxReply{
		surbID:     unknownSurbID,
		ciphertext: []byte("some-ciphertext"),
	}

	// Should not panic
	d.handleReply(reply)
}

func TestCleanupForAppIDWithARQ(t *testing.T) {
	d := &Daemon{
		arqSurbIDMap:       make(map[[sphinxConstants.SURBIDLength]byte]*ARQMessage),
		arqEnvelopeHashMap: make(map[[32]byte]*[sphinxConstants.SURBIDLength]byte),
		replies:            make(map[[sphinxConstants.SURBIDLength]byte]replyDescriptor),
		decoys:             make(map[[sphinxConstants.SURBIDLength]byte]replyDescriptor),
		replyLock:          new(sync.Mutex),
	}

	logBackend, err := log.New("", "debug", false)
	require.NoError(t, err)
	d.logbackend = logBackend
	d.log = logBackend.GetLogger("test")

	appID := &[AppIDLength]byte{}
	copy(appID[:], []byte("cleanup-app-id01"))

	otherAppID := &[AppIDLength]byte{}
	copy(otherAppID[:], []byte("other-app-id-002"))

	// Add ARQ entries for both app IDs
	surbID1 := [sphinxConstants.SURBIDLength]byte{}
	copy(surbID1[:], []byte("arq-surb-id-0001"))
	surbID2 := [sphinxConstants.SURBIDLength]byte{}
	copy(surbID2[:], []byte("arq-surb-id-0002"))

	d.replyLock.Lock()
	d.arqSurbIDMap[surbID1] = &ARQMessage{AppID: appID, SURBID: &surbID1}
	d.arqSurbIDMap[surbID2] = &ARQMessage{AppID: otherAppID, SURBID: &surbID2}
	d.replyLock.Unlock()

	d.cleanupForAppID(appID)

	d.replyLock.Lock()
	require.NotContains(t, d.arqSurbIDMap, surbID1, "ARQ for cleaned app should be removed")
	require.Contains(t, d.arqSurbIDMap, surbID2, "ARQ for other app should remain")
	d.replyLock.Unlock()
}

func TestCleanupForAppIDNoState(t *testing.T) {
	d := &Daemon{
		arqSurbIDMap: make(map[[sphinxConstants.SURBIDLength]byte]*ARQMessage),
		replies:      make(map[[sphinxConstants.SURBIDLength]byte]replyDescriptor),
		decoys:       make(map[[sphinxConstants.SURBIDLength]byte]replyDescriptor),
		replyLock:    new(sync.Mutex),
	}

	logBackend, err := log.New("", "debug", false)
	require.NoError(t, err)
	d.logbackend = logBackend
	d.log = logBackend.GetLogger("test")

	appID := &[AppIDLength]byte{}
	copy(appID[:], []byte("nonexistent-ap01"))

	// Should not panic when no state exists
	d.cleanupForAppID(appID)
}

func TestDaemonStartStopMultiple(t *testing.T) {
	cfg, err := config.LoadFile("testdata/client.toml")
	require.NoError(t, err)

	port, err := getFreePort()
	require.NoError(t, err)
	cfg.ListenAddress = fmt.Sprintf("localhost:%d", port)

	d, err := NewDaemon(cfg)
	require.NoError(t, err)

	err = d.Start()
	require.NoError(t, err)

	// Multiple Shutdown calls should not panic (sync.Once)
	d.Shutdown()
	d.Shutdown()
}
