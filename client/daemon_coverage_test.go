// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package client

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/client/thin"
	sphinxConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
)


func TestSendLoopDecoyNoPKIDoc(t *testing.T) {
	d, _, testAppID, _, _ := setupFullClient(t)

	d.client.pki.docs = sync.Map{}

	request := &Request{
		AppID:         testAppID,
		SendLoopDecoy: &SendLoopDecoy{},
	}

	// Should not panic, just log a warning
	d.sendLoopDecoy(request)
}

func TestEgressWorkerAllRequestTypes(t *testing.T) {
	d, _, testAppID, responseCh, _ := setupFullClient(t)

	d.egressCh = make(chan *Request, 10)
	go d.egressWorker()
	t.Cleanup(func() { d.Halt() })

	// Test SendLoopDecoy through egressWorker
	d.egressCh <- &Request{
		AppID:         testAppID,
		SendLoopDecoy: &SendLoopDecoy{},
	}

	// Test EncryptRead through egressWorker
	readQueryID := &[thin.QueryIDLength]byte{}
	copy(readQueryID[:], []byte("egress-read-0000"))
	d.egressCh <- &Request{
		AppID: testAppID,
		EncryptRead: &thin.EncryptRead{
			QueryID: readQueryID,
			// nil ReadCap will trigger error response
		},
	}

	select {
	case resp := <-responseCh:
		require.NotNil(t, resp.EncryptReadReply)
		require.NotEqual(t, thin.ThinClientSuccess, resp.EncryptReadReply.ErrorCode)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for EncryptRead error response")
	}

	// Test EncryptWrite through egressWorker
	writeQueryID := &[thin.QueryIDLength]byte{}
	copy(writeQueryID[:], []byte("egress-write0000"))
	d.egressCh <- &Request{
		AppID: testAppID,
		EncryptWrite: &thin.EncryptWrite{
			QueryID: writeQueryID,
			// nil WriteCap will trigger error response
		},
	}

	select {
	case resp := <-responseCh:
		require.NotNil(t, resp.EncryptWriteReply)
		require.NotEqual(t, thin.ThinClientSuccess, resp.EncryptWriteReply.ErrorCode)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for EncryptWrite error response")
	}

	// Test NextMessageBoxIndex through egressWorker
	nmbQueryID := &[thin.QueryIDLength]byte{}
	copy(nmbQueryID[:], []byte("egress-nextmb000"))
	d.egressCh <- &Request{
		AppID: testAppID,
		NextMessageBoxIndex: &thin.NextMessageBoxIndex{
			QueryID: nmbQueryID,
			// nil MessageBoxIndex will trigger error response
		},
	}

	select {
	case resp := <-responseCh:
		require.NotNil(t, resp.NextMessageBoxIndexReply)
		require.NotEqual(t, thin.ThinClientSuccess, resp.NextMessageBoxIndexReply.ErrorCode)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for NextMessageBoxIndex error response")
	}
}

func TestIngressWorkerGCSurbID(t *testing.T) {
	d, _, _, _, _ := setupFullClient(t)

	d.ingressCh = make(chan *sphinxReply, 10)
	d.gcSurbIDCh = make(chan *[sphinxConstants.SURBIDLength]byte, 10)
	d.gcReplyCh = make(chan *gcReply, 10)

	go d.ingressWorker()
	t.Cleanup(func() { d.Halt() })

	// Add a reply descriptor
	surbID := &[sphinxConstants.SURBIDLength]byte{}
	_, err := rand.Reader.Read(surbID[:])
	require.NoError(t, err)

	d.replyLock.Lock()
	d.replies[*surbID] = replyDescriptor{
		appID:   &[AppIDLength]byte{},
		surbKey: []byte("key"),
	}
	d.replyLock.Unlock()

	// Send GC signal
	d.gcSurbIDCh <- surbID

	// Wait for processing
	time.Sleep(100 * time.Millisecond)

	// Verify it was removed
	d.replyLock.Lock()
	_, found := d.replies[*surbID]
	d.replyLock.Unlock()
	require.False(t, found, "reply should have been garbage collected")
}

func TestIngressWorkerGCReplyNoConnection(t *testing.T) {
	d, _, _, _, _ := setupFullClient(t)

	d.ingressCh = make(chan *sphinxReply, 10)
	d.gcSurbIDCh = make(chan *[sphinxConstants.SURBIDLength]byte, 10)
	d.gcReplyCh = make(chan *gcReply, 10)

	go d.ingressWorker()
	t.Cleanup(func() { d.Halt() })

	// Send a GC reply for an unknown app ID (no connection)
	unknownAppID := &[AppIDLength]byte{}
	copy(unknownAppID[:], []byte("unknown-app-id00"))
	msgID := &[MessageIDLength]byte{}
	_, err := rand.Reader.Read(msgID[:])
	require.NoError(t, err)

	d.gcReplyCh <- &gcReply{
		id:    msgID,
		appID: unknownAppID,
	}

	// Should not panic — just logs an error
	time.Sleep(100 * time.Millisecond)
}

func TestIngressWorkerGCReplyWithConnection(t *testing.T) {
	d, _, testAppID, responseCh, _ := setupFullClient(t)

	d.ingressCh = make(chan *sphinxReply, 10)
	d.gcSurbIDCh = make(chan *[sphinxConstants.SURBIDLength]byte, 10)
	d.gcReplyCh = make(chan *gcReply, 10)

	go d.ingressWorker()
	t.Cleanup(func() { d.Halt() })

	msgID := &[MessageIDLength]byte{}
	_, err := rand.Reader.Read(msgID[:])
	require.NoError(t, err)

	d.gcReplyCh <- &gcReply{
		id:    msgID,
		appID: testAppID,
	}

	select {
	case resp := <-responseCh:
		require.NotNil(t, resp.MessageIDGarbageCollected)
		require.Equal(t, msgID, resp.MessageIDGarbageCollected.MessageID)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for GC response")
	}
}
