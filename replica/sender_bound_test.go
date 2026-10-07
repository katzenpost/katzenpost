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
