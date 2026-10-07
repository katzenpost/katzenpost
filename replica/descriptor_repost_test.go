// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/epochtime/periodtest"
	"github.com/katzenpost/katzenpost/core/pki"
)

func setReplicaEpochClock(t *testing.T, now uint64, elapsed time.Duration) {
	saved := epochtime.Epoch
	epochtime.Epoch = time.Now().Add(-(time.Duration(now)*epochtime.Period() + elapsed))
	t.Cleanup(func() { epochtime.Epoch = saved })
}

func TestReplicaUpdateTimerRepostsInsideTheUploadWindow(t *testing.T) {
	periodtest.Run(t, func(t *testing.T, p time.Duration) {
		const now = 1000
		setReplicaEpochClock(t, now, time.Second)
		w, cleanup := createPublishDescriptorTestWorker(t, &mockReplicaPKIClient{postErr: pki.ErrInvalidPostEpoch})
		defer cleanup()
		w.SetDocumentForEpoch(now, &pki.Document{Epoch: now}, nil)
		require.ErrorIs(t, w.publishDescriptorIfNeeded(context.Background()), pki.ErrInvalidPostEpoch)

		timer := time.NewTimer(time.Hour)
		defer timer.Stop()
		w.updateTimer(timer)
		if p == 20*time.Minute {
			select {
			case <-timer.C:
				require.FailNow(t, "replica reposted a rejected descriptor faster than the bounded cadence")
			case <-time.After(2 * time.Second):
			}
			return
		}
		select {
		case <-timer.C:
		case <-time.After(p/96 + 2*time.Second):
			require.FailNow(t, "replica slept past the upload window without its descriptor posted")
		}
	})
}

func TestReplicaUpdateTimerRepostsAtTheBoundedCadenceAfterAnyFailedPost(t *testing.T) {
	periodtest.Run(t, func(t *testing.T, p time.Duration) {
		const now = 1000
		setReplicaEpochClock(t, now, time.Second)
		failure := errors.New("Post(1001) failed: 2/3 successes, 2/3 rejections")
		w, cleanup := createPublishDescriptorTestWorker(t, &mockReplicaPKIClient{postErr: failure})
		defer cleanup()
		w.SetDocumentForEpoch(now, &pki.Document{Epoch: now}, nil)
		require.ErrorIs(t, w.publishDescriptorIfNeeded(context.Background()), failure)

		timer := time.NewTimer(time.Hour)
		defer timer.Stop()
		w.updateTimer(timer)
		if p == 20*time.Minute {
			select {
			case <-timer.C:
				require.FailNow(t, "replica reposted after a failed post faster than the bounded cadence")
			case <-time.After(2 * time.Second):
			}
			return
		}
		select {
		case <-timer.C:
		case <-time.After(p/96 + 2*time.Second):
			require.FailNow(t, "replica slept past the upload window without its descriptor posted")
		}
	})
}
