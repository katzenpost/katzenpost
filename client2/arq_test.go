//go:build time

// SPDX-FileCopyrightText: © 2023 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only
package client2

import (
	"os"
	"sync"
	"testing"
	"time"

	"github.com/charmbracelet/log"
	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/crypto/rand"
)

var mockRTT time.Duration = time.Second * 2

type mockComposerSender struct {
	t        *testing.T
	requests []*Request
	ch       chan bool
	lock     sync.RWMutex
}

func (m *mockComposerSender) SendCiphertext(request *Request) ([]byte, time.Duration, error) {
	m.t.Log("SendCiphertext")
	m.lock.Lock()
	m.requests = append(m.requests, request)
	m.lock.Unlock()

	defer func() {
		m.lock.RLock()
		if len(m.requests) == 2 {
			m.ch <- false
		}
		m.lock.RUnlock()

		m.t.Log("SendCiphertext return")
	}()

	return []byte("packet"), mockRTT, nil
}

type mockSentEventSender struct{}

func (m *mockSentEventSender) SentEvent(response *Response) {}

// disable for now; github CI cannot properly handle any tests that use time.
func TestARQ(t *testing.T) {
	sphinxComposerSender := &mockComposerSender{
		t:        t,
		requests: make([]*Request, 0),
		ch:       make(chan bool, 0),
	}
	logbackend := os.Stderr
	level, err := log.ParseLevel("debug")
	require.NoError(t, err)
	logger := log.NewWithOptions(logbackend, log.Options{
		ReportTimestamp: true,
		Prefix:          "TestARQ",
		Level:           level,
	})

	m := &mockSentEventSender{}

	arq := NewARQ(sphinxComposerSender, m, logger)
	arq.Start()

	appid := new([AppIDLength]byte)
	_, err = rand.Reader.Read(appid[:])
	require.NoError(t, err)

	id := &[MessageIDLength]byte{}
	payload := []byte("hello world")
	providerHash := &[32]byte{}
	_, err = rand.Reader.Read(providerHash[:])
	require.NoError(t, err)
	require.NotNil(t, providerHash)

	queueID := []byte{1, 2, 3, 4, 5, 6, 7}

	require.Equal(t, 0, arq.timerQueue.Len())

	_, err = arq.Send(appid, id, payload, providerHash, queueID)
	require.NoError(t, err)

	time.Sleep(1 * time.Second)
	require.Equal(t, 1, arq.timerQueue.Len())

	sphinxComposerSender.lock.Lock()
	surbid1 := sphinxComposerSender.requests[0].SURBID
	sphinxComposerSender.lock.Unlock()

	require.True(t, arq.Has(surbid1))

	t.Log("awaiting channel <-sphinxComposerSender.ch")
	<-sphinxComposerSender.ch

	require.Equal(t, 2, len(sphinxComposerSender.requests))

	sphinxComposerSender.lock.Lock()
	surbid2 := sphinxComposerSender.requests[1].SURBID
	sphinxComposerSender.lock.Unlock()

	require.True(t, arq.Has(surbid2))
	arq.HandleAck(surbid2)

	require.False(t, arq.Has(surbid2))
	require.False(t, arq.Has(surbid1))

	arq.Stop()
}
