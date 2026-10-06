// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/epochtime/periodtest"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/pki"
)

func TestReplicaPrefetchesNextDocument(t *testing.T) {
	periodtest.Run(t, func(t *testing.T, p time.Duration) {
		if p != 2*time.Minute {
			return
		}
		const now = 1000
		saved := epochtime.Epoch
		epochtime.Epoch = time.Now().Add(-(time.Duration(now)*p + 11*(p/16) + time.Second))
		t.Cleanup(func() { epochtime.Epoch = saved })

		backend, err := log.New("", "ERROR", false)
		require.NoError(t, err)
		w := &PKIWorker{
			WorkerBase:         pki.NewWorkerBase(nil, backend.GetLogger("replica-pki")),
			lastPublishedEpoch: now + 1,
		}
		w.SetDocumentForEpoch(now, &pki.Document{Epoch: now}, nil)

		timer := time.NewTimer(time.Hour)
		defer timer.Stop()
		w.updateTimer(timer)
		select {
		case <-timer.C:
		case <-time.After(p/32 + 2*time.Second):
			t.Fatal("replica slept toward the epoch boundary without doc N+1")
		}
	})
}
