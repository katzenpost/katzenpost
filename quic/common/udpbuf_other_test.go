// SPDX-License-Identifier: AGPL-3.0-only

//go:build !unix

package common

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNonUnixUDPBuffersAreUnknown(t *testing.T) {
	b := readUDPBuffers(nil)
	require.Zero(t, b.Receive)
	require.Zero(t, b.Send)
	require.Empty(t, b.Warning())
}
