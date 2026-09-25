// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/epochtime"
)

func TestConsensusBytesIdenticalAcrossAuthorities(t *testing.T) {
	epoch, _, _ := epochtime.Now()
	docs := runVoteScenario(t, 5, epoch+2, nil)
	require.Len(t, docs, 5)
	first, err := docs[0].MarshalCertificate()
	require.NoError(t, err)
	for i := 1; i < len(docs); i++ {
		require.Equal(t, docs[0].SharedRandomValue, docs[i].SharedRandomValue, "authority %d SRV differs", i)
		require.Equal(t, docs[0].PriorSharedRandom, docs[i].PriorSharedRandom, "authority %d prior SRV differs", i)
		raw, err := docs[i].MarshalCertificate()
		require.NoError(t, err)
		require.True(t, bytes.Equal(first, raw), "authority %d signed different bytes", i)
	}
}
