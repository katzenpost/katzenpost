// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/rand"
)

func TestShard(t *testing.T) {
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

	shard := Shard(boxid, keys)

	t.Log("Shard:")
	for _, s := range shard {
		t.Logf("entry: %x", s)
	}
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

func BenchmarkShard(b *testing.B) {
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
		shard = Shard(boxid, keys)
	}

	shard2 = shard
	shard = shard2
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
