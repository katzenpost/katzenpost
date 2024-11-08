// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/rand"
)

func TestShardSimple(t *testing.T) {
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

	shards1 := Shard2(boxid1, serverIdKeys)
	shards2 := Shard2(boxid2, serverIdKeys)

	require.NotEqual(t, shards1, shards2)
}

func TestShard2(t *testing.T) {
	numServers := 10
	keySize := 32
	keys := make([][]byte, numServers)
	for i := 0; i < numServers; i++ {
		keys[i] = make([]byte, keySize)
		_, err := rand.Reader.Read(keys[i])
		require.NoError(t, err)
	}

	boxid := &[32]byte{}
	_, err := rand.Reader.Read(boxid[:])
	require.NoError(t, err)

	shard := Shard2(boxid, keys)

	t.Log("Shard:")
	for _, s := range shard {
		t.Logf("entry: %x", s)
	}
}

func BenchmarkShard2(b *testing.B) {
	numServers := 10
	keySize := 32
	keys := make([][]byte, numServers)
	for i := 0; i < numServers; i++ {
		keys[i] = make([]byte, keySize)
		_, err := rand.Reader.Read(keys[i])
		require.NoError(b, err)
	}

	boxid := &[32]byte{}
	_, err := rand.Reader.Read(boxid[:])
	require.NoError(b, err)

	var shard [][]byte
	var shard2 [][]byte
	for i := 0; i < b.N; i++ {
		shard = Shard2(boxid, keys)
	}

	shard2 = shard
	shard = shard2
}
