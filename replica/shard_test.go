// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/rand"
)

func TestShard(t *testing.T) {
	boxid1 := &[32]byte{}
	boxid2 := &[32]byte{}

	_, err := rand.Reader.Read(boxid1[:])
	require.NoError(t, err)
	_, err = rand.Reader.Read(boxid2[:])
	require.NoError(t, err)

	serverIdKeys := make([][]byte, 5)

	for i := 0; i < 5; i++ {
		serverIdKeys[i] = make([]byte, 32)
		_, err := rand.Reader.Read(serverIdKeys[i])
		require.NoError(t, err)
	}

	shards1 := Shard(boxid1, serverIdKeys)
	shards2 := Shard(boxid2, serverIdKeys)

	require.NotEqual(t, shards1, shards2)
}
