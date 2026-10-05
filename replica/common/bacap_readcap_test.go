// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"testing"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/stretchr/testify/require"
)

// A read cap and index that arrive from outside must not make box ID
// derivation panic, whatever bytes they hold.
func TestBoxIDFromCraftedReadCapDoesNotPanic(t *testing.T) {
	craftedIndex := make([]byte, bacap.MessageBoxIndexSize)
	for i := range craftedIndex {
		craftedIndex[i] = 0xf6
	}
	for _, rcBytes := range [][]byte{
		make([]byte, bacap.ReadCapSize), // all-zero root key, a small-order point
		append([]byte{0xf6}, make([]byte, bacap.ReadCapSize-1)...),
		append(make([]byte, 32), craftedIndex...),
	} {
		rc, err := bacap.ReadCapFromBytes(rcBytes)
		if err != nil {
			continue
		}
		idx, err := bacap.NewEmptyMessageBoxIndexFromBytes(craftedIndex)
		require.NoError(t, err)
		require.NotPanics(t, func() {
			_, _ = idx.BoxIDForContext(rc, []byte("pigeonhole context"))
		}, "a crafted ReadCap must not panic in BoxIDForContext")
	}
}
