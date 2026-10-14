// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUnknownUDPBuffersDoNotWarn(t *testing.T) {
	require.Empty(t, UDPBuffers{}.Warning(), "socket buffers that could not be read were reported as too small")
}
