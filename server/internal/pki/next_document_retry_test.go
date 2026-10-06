// SPDX-License-Identifier: AGPL-3.0-only

package pki

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/epochtime/periodtest"
	"github.com/katzenpost/katzenpost/server/internal/pkicache"
)

func setEpochClock(t *testing.T, now uint64, elapsed time.Duration) {
	saved := epochtime.Epoch
	epochtime.Epoch = time.Now().Add(-(time.Duration(now)*epochtime.Period() + elapsed))
	t.Cleanup(func() { epochtime.Epoch = saved })
}

func TestUpdateTimerRetriesNextDocumentAfterPublication(t *testing.T) {
	periodtest.Run(t, func(t *testing.T, p time.Duration) {
		if p != 2*time.Minute {
			return
		}
		const now = 1000
		setEpochClock(t, now, 5*(p/8)+time.Second)
		f := newAuthFixture(t)
		ent, _ := f.entry(t, now, -1, 0)
		mp, _ := newRotationPKI(t, &fakeMixKeys{})
		mp.docs = map[uint64]*pkicache.Entry{now: ent}

		timer := time.NewTimer(time.Hour)
		defer timer.Stop()
		mp.updateTimer(timer)
		select {
		case <-timer.C:
		case <-time.After(recheckInterval() + 2*time.Second):
			require.FailNow(t, "mix slept toward the epoch boundary without doc N+1")
		}
	})
}
