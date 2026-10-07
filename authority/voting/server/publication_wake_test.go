// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/epochtime"
)

func fsmAtPublication(t *testing.T, st *state) (uint64, time.Duration) {
	p := clockLogFile(t, st)
	savedEpoch := epochtime.Epoch
	t.Cleanup(func() { epochtime.Epoch = savedEpoch })
	now, _, _ := epochtime.Now()
	period := epochtime.Period()
	epochtime.Epoch = time.Now().Add(-(time.Duration(now)*period + PublishConsensusDeadline() + time.Second))
	st.state = stateAcceptSignature
	st.fsm()
	var sleep time.Duration
	require.Eventually(t, func() bool {
		b, err := os.ReadFile(p)
		require.NoError(t, err)
		m := regexp.MustCompile(`Consensus (?:successful|failed).*sleeping for (\S+)`).FindSubmatch(b)
		if m == nil {
			return false
		}
		sleep, err = time.ParseDuration(string(m[1]))
		require.NoError(t, err)
		return true
	}, 5*time.Second, 20*time.Millisecond)
	return now, sleep
}

func TestPublicationWakeAfterThreshold(t *testing.T) {
	states, _, epoch, docs := runPartitionedRound(t, 3, [][]int{{0, 1, 2}})
	require.Len(t, docs, 3)
	st := states[0]
	st.votingEpoch = epoch
	_, sleep := fsmAtPublication(t, st)
	require.Equal(t, stateAcceptDescriptor, st.state)
	require.Equal(t, epoch+1, st.votingEpoch)
	require.InDelta(t, epochtime.Period()-PublishConsensusDeadline()-time.Second+MixPublishDeadline(), sleep, float64(time.Second))
}

func TestPublicationWakeWithoutThreshold(t *testing.T) {
	states, _, epoch, docs := runPartitionedRound(t, 4, [][]int{{0, 1}, {2, 3}})
	require.Empty(t, docs)
	st := states[0]
	st.votingEpoch = epoch - 1
	now, sleep := fsmAtPublication(t, st)
	require.Equal(t, stateBootstrap, st.state)
	require.Equal(t, now+2, st.votingEpoch)
	require.InDelta(t, epochtime.Period()-PublishConsensusDeadline()-time.Second, sleep, float64(time.Second))
}
