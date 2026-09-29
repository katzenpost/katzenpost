// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"testing"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/stretchr/testify/require"
)

func TestStatefulReaderFromCraftedBytesReturnsError(t *testing.T) {
	sr, err := bacap.NewStatefulReaderFromBytes([]byte("\xf6"))
	if err != nil {
		return
	}
	require.NotPanics(t, func() {
		_, err = sr.NextBoxID()
	}, "a crafted StatefulReader must not panic in NextBoxID")
	require.Error(t, err, "a crafted StatefulReader must fail NextBoxID with an error, not panic")
}
