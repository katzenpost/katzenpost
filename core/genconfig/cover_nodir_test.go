// SPDX-License-Identifier: AGPL-3.0-only

package genconfig

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNoCoverCreatesNoHostDirs(t *testing.T) {
	out := t.TempDir()
	s := &Katzenpost{OutDir: out, BaseDir: "/conf"}
	require.Empty(t, s.coverDir("mix1"))
	_, err := os.Stat(filepath.Join(out, "coverage"))
	require.True(t, os.IsNotExist(err))
}

func TestInitializeKatzenpostCover(t *testing.T) {
	require.True(t, InitializeKatzenpost(&Config{Cover: true}).Cover)
	require.False(t, InitializeKatzenpost(&Config{}).Cover)
}
