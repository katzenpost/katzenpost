// SPDX-License-Identifier: AGPL-3.0-only

package log

import (
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLogWriterTakesABlankWrite(t *testing.T) {
	b, err := New(filepath.Join(t.TempDir(), "blank.log"), "DEBUG", false)
	require.NoError(t, err)
	t.Cleanup(func() { b.Close() })
	n, err := io.Copy(b.GetLogWriter("blank", "DEBUG"), strings.NewReader(" \n"))
	require.NoError(t, err)
	require.Equal(t, int64(2), n)
}
