// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/pki"
)

func nextWeekBoundaryEpoch() uint64 {
	now, _, _ := epochtime.Now()
	return (now+5)/epochtime.WeekOfEpochs*epochtime.WeekOfEpochs + epochtime.WeekOfEpochs
}

func priorDocument(epoch uint64) (*pki.Document, [][]byte) {
	thisWeek := bytes.Repeat([]byte{0xaa}, 32)
	lastWeek := bytes.Repeat([]byte{0xbb}, 32)
	return &pki.Document{
		Epoch:             epoch,
		GenesisEpoch:      epoch - 1000,
		SharedRandomValue: bytes.Repeat([]byte{0xcc}, 32),
		PriorSharedRandom: [][]byte{thisWeek, lastWeek},
	}, [][]byte{thisWeek, lastWeek}
}

func TestPriorSharedRandomRotatesOnceAtWeekBoundary(t *testing.T) {
	require := require.New(t)
	epoch := nextWeekBoundaryEpoch()
	prior, was := priorDocument(epoch - 1)
	docs := runVoteScenario(t, 3, epoch, prior)
	require.Len(docs, 3)
	for _, d := range docs {
		require.Len(d.SharedRandomValue, 32)
		require.NotEqual(make([]byte, 32), d.SharedRandomValue)
		require.Equal([][]byte{d.SharedRandomValue, was[0]}, d.PriorSharedRandom)
	}
}

func TestPriorSharedRandomUnchangedOffWeekBoundary(t *testing.T) {
	require := require.New(t)
	epoch := nextWeekBoundaryEpoch() + 1
	prior, was := priorDocument(epoch - 1)
	docs := runVoteScenario(t, 3, epoch, prior)
	require.Len(docs, 3)
	for _, d := range docs {
		require.Equal(was, d.PriorSharedRandom)
	}
}

func TestPriorSharedRandomAtGenesis(t *testing.T) {
	require := require.New(t)
	epoch := nextWeekBoundaryEpoch() + 2
	docs := runVoteScenario(t, 3, epoch, nil)
	require.Len(docs, 3)
	for _, d := range docs {
		require.Equal(epoch, d.GenesisEpoch)
		require.Equal([][]byte{d.SharedRandomValue, d.SharedRandomValue}, d.PriorSharedRandom)
	}
}
