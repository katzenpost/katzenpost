// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
)

// TestDescriptorEpochTolerance proves the descriptor epoch acceptance window is
// governed by the configured DescriptorEpochTolerance, not a fixed +-1. The
// method reads the field, so a non-default tolerance changes which epochs are
// accepted at the boundary.
func TestDescriptorEpochTolerance(t *testing.T) {
	const now = uint64(1000)

	srvFor := func(tol uint64) *Server {
		return &Server{cfg: &config.Config{Server: &config.Server{DescriptorEpochTolerance: tol}}}
	}

	t.Run("default tolerance 1", func(t *testing.T) {
		s := srvFor(1)
		require.True(t, s.descriptorEpochOK(now, now))
		require.True(t, s.descriptorEpochOK(now, now+1))
		require.True(t, s.descriptorEpochOK(now, now-1))
		require.False(t, s.descriptorEpochOK(now, now+2))
		require.False(t, s.descriptorEpochOK(now, now-2))
	})

	t.Run("tolerance 2 widens the window", func(t *testing.T) {
		s := srvFor(2)
		require.True(t, s.descriptorEpochOK(now, now+2), "now+2 must be accepted at tolerance 2 (rejected under the default 1)")
		require.True(t, s.descriptorEpochOK(now, now-2))
		require.False(t, s.descriptorEpochOK(now, now+3))
		require.False(t, s.descriptorEpochOK(now, now-3))
	})
}
