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

var mockRTT time.Duration = 1 * time.Second

type mockComposerSender struct {
	t                *testing.T
	requests         []*Request
	ch               chan bool
	lock             sync.RWMutex
	targetRequestNum int
}

func (m *mockComposerSender) SendCiphertext(request *Request) ([]byte, time.Duration, error) {
	m.t.Log("START ------------ SendCiphertext --------------------------------------------------------------------------------------")
	defer m.t.Log("END ------------ SendCiphertext --------------------------------------------------------------------------------------")
	m.lock.Lock()
	defer m.lock.Unlock()
	m.requests = append(m.requests, request)

	defer func() {
		if len(m.requests) == m.targetRequestNum {
			m.ch <- false
		}

		m.t.Log("SendCiphertext return")
	}()

	return []byte("packet"), mockRTT, nil
}

func newMockComposerSender(t *testing.T, targetRequestNum int) *mockComposerSender {
	return &mockComposerSender{
		t:                t,
		requests:         make([]*Request, 0),
		ch:               make(chan bool, 0),
		targetRequestNum: targetRequestNum,
	}
}

type mockSentEventSender struct{}

func (m *mockSentEventSender) SentEvent(response *Response) {}

// disable for now; github CI cannot properly handle any tests that use time.
func TestARQ(t *testing.T) {
	targetRequestNum := 3
	sphinxComposerSender := newMockComposerSender(t, targetRequestNum)

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

	sentTime := time.Now()

	sphinxComposerSender.lock.Lock()
	surbid1 := sphinxComposerSender.requests[0].SURBID
	sphinxComposerSender.lock.Unlock()

	require.True(t, arq.Has(surbid1))

	t.Log("awaiting channel <-sphinxComposerSender.ch")

	<-sphinxComposerSender.ch
	cur := time.Now()
	timeDiff := cur.Sub(sentTime)

	t.Logf("---------->>> timeDiff %s", timeDiff)
	timeslop := 3 * time.Second
	targetRTT := time.Until(time.Now().Add(mockRTT * time.Duration(targetRequestNum-1)).Add(RoundTripTimeSlop * time.Duration(targetRequestNum-1)).Add(timeslop))

	t.Logf("------------->>> WANT RTT %s", targetRTT)

	require.True(t, targetRTT > timeDiff)

	require.Equal(t, targetRequestNum, len(sphinxComposerSender.requests))
	require.False(t, arq.Has(surbid1))

	sphinxComposerSender.lock.Lock()
	surbid3 := sphinxComposerSender.requests[2].SURBID
	require.True(t, arq.Has(surbid3))
	sphinxComposerSender.lock.Unlock()

	arq.HandleAck(surbid3)

	require.False(t, arq.Has(surbid3))
	require.False(t, arq.Has(surbid1))

	arq.Stop()
}
