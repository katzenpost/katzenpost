// SPDX-FileCopyrightText: © 2023 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only
package client2

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var mockRTT time.Duration = time.Second * 3

type mockComposerSender struct {
	t        *testing.T
	requests []*Request
}

func (m *mockComposerSender) ComposeSphinxPacket(request *Request) ([]byte, []byte, time.Duration, error) {
	m.t.Log("ComposeSphinxPacket")
	m.requests = append(m.requests, request)
	return []byte("packet"), []byte("key"), mockRTT, nil
}

func (m *mockComposerSender) SendSphinxPacket(pkt []byte) error {
	m.t.Log("SendSphinxPacket")
	return nil
}

func TestARQ(t *testing.T) {
	sphinxComposerSender := &mockComposerSender{
		t:        t,
		requests: make([]*Request, 0),
	}
	logbackend := os.Stderr
	arq := NewARQ(sphinxComposerSender, logbackend)
	arq.Start()

	appid := uint64(0)
	id := &[MessageIDLength]byte{}
	payload := []byte("hello world")
	providerHash := &[32]byte{}
	queueID := []byte{1, 2, 3, 4, 5, 6, 7}

	require.Equal(t, 0, arq.timerQueue.Len())

	err := arq.Send(appid, id, payload, providerHash, queueID)
	require.NoError(t, err)
	require.Equal(t, 1, arq.timerQueue.Len())

	surbid1 := sphinxComposerSender.requests[0].SURBID
	require.True(t, arq.Has(surbid1))

	sleepDuration := mockRTT + RoundTripTimeSlop + (time.Second * 1)
	t.Logf("test thread sleeping for %s", sleepDuration)
	time.Sleep(sleepDuration)

	require.Equal(t, 1, arq.timerQueue.Len())
	require.Equal(t, 2, len(sphinxComposerSender.requests))
	surbid2 := sphinxComposerSender.requests[1].SURBID

	require.True(t, arq.Has(surbid2))
	arq.HandleAck(surbid2)
	require.False(t, arq.Has(surbid2))
	require.False(t, arq.Has(surbid1))

	arq.Stop()
}
