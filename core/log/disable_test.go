// SPDX-License-Identifier: AGPL-3.0-only

package log

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDisabledBackendDiscardsWithoutPanicking(t *testing.T) {
	b, err := New("", "DEBUG", true)
	require.NoError(t, err)
	l := b.GetLogger("disabled")
	require.NotPanics(t, func() {
		l.Errorf("dropped %d", 1)
		l.Debug("dropped")
		b.GetGoLogger("disabled", "ERROR").Print("dropped")
	})
	require.NoError(t, b.Rotate())
	require.NoError(t, b.Close())
}
