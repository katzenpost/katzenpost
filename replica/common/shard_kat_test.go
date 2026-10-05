// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestShardKAT(t *testing.T) {
	var box [32]byte
	for i := range box {
		box[i] = byte(i)
	}
	keys := [][]byte{}
	for i := 0; i < 5; i++ {
		keys = append(keys, []byte{byte(i), byte(i + 1), byte(i + 2)})
	}
	want := [][]byte{{3, 4, 5}, {0, 1, 2}}
	require.Equal(t, want, Shard2(&box, keys))
	require.Equal(t, want, Shard(&box, keys))
}
