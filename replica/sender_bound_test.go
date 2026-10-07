// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/log"
)

func TestDelayedReplyEmitterBoundsInFlight(t *testing.T) {
	logBackend, err := log.New("", "ERROR", false)
	require.NoError(t, err)

	out := make(chan *senderRequest, 8)
	before := runtime.NumGoroutine()
	e := newDelayedReplyEmitter(out, logBackend, "test", func() time.Duration { return 0 })
	defer e.Halt()

	for i := 0; i < 500; i++ {
		e.Enqueue(&senderRequest{})
	}
	time.Sleep(200 * time.Millisecond)

	after := runtime.NumGoroutine()
	t.Logf("goroutines before=%d after=%d", before, after)
	require.LessOrEqual(t, after-before, cap(out)+1)
}

func TestDelayedReplyEmitterReleasesStuckReplies(t *testing.T) {
	logBackend, err := log.New("", "ERROR", false)
	require.NoError(t, err)

	out := make(chan *senderRequest, 8)
	e := newDelayedReplyEmitter(out, logBackend, "test", func() time.Duration { return 0 })
	e.handoffTimeout = 300 * time.Millisecond
	defer e.Halt()

	for i := 0; i < 500; i++ {
		e.Enqueue(&senderRequest{})
	}
	require.LessOrEqual(t, e.outstanding.Load(), int64(cap(out)))

	require.Eventually(t, func() bool {
		return e.outstanding.Load() == 0
	}, 5*time.Second, 10*time.Millisecond)
	require.Equal(t, cap(out), len(out))

	for len(out) > 0 {
		<-out
	}
	e.Enqueue(&senderRequest{recvAt: time.Now()})
	select {
	case <-out:
	case <-time.After(5 * time.Second):
		t.Fatal("reply not emitted after the egress drained")
	}
}
