// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/epochtime"
)

func TestReplicaEpoch(t *testing.T) {
	epoch, _, _ := epochtime.Now()
	replicaEpoch, _, _ := ReplicaNow()
	require.Equal(t, replicaEpoch, ConvertNormalToReplicaEpoch(epoch))
	require.Equal(t, epoch, ConvertReplicaToNormalEpoch(replicaEpoch))
}
