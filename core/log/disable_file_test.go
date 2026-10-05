// SPDX-License-Identifier: AGPL-3.0-only

package log

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDisabledBackendWritesNothingToItsFile(t *testing.T) {
	f := filepath.Join(t.TempDir(), "disabled.log")
	b, err := New(f, "DEBUG", true)
	require.NoError(t, err)
	b.GetLogger("disabled").Error("dropped")
	n, err := b.GetLogWriter("disabled", "ERROR").Write([]byte("dropped\n"))
	require.NoError(t, err)
	require.Equal(t, len("dropped\n"), n)
	require.NoError(t, b.Rotate())
	require.NoFileExists(t, f)
}

func TestDiscardCloserWriteReportsFullLength(t *testing.T) {
	n, err := newDiscardCloser().Write([]byte("abc"))
	require.NoError(t, err)
	require.Equal(t, 3, n)
}
