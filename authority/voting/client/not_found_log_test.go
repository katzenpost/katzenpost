// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/wire/commands"
)

func TestNotFoundIsNotLoggedAsAnError(t *testing.T) {
	p := filepath.Join(t.TempDir(), "client.log")
	lb, err := log.New(p, "WARNING", false)
	require.NoError(t, err)
	t.Cleanup(func() { _ = lb.Close() })
	notFound, gone := commands.ConsensusNotFound, commands.ConsensusGone
	err = fetchWithCodesLog(t, []int{notFound, notFound, gone, unreachable}, 41600, lb)
	require.Equal(t, pki.ErrNoDocument, err)
	b, err := os.ReadFile(p)
	require.NoError(t, err)
	out := string(b)
	require.NotContains(t, out, fmt.Sprintf("consensus error code %d", notFound))
	require.Regexp(t, fmt.Sprintf(`ERRO .*Get: authority41602: consensus error code %d`, gone), out)
	require.Regexp(t, `ERRO .*Get: authority41603: .*connection refused`, out)
}
