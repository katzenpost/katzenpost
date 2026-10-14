// SPDX-License-Identifier: AGPL-3.0-only

//go:build !noprometheus

package instrument

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUnknownUDPBuffersAreNotExported(t *testing.T) {
	const address = "192.0.2.1:4242"
	QUICUDPBuffers(address, 0, 0)
	require.False(t, quicUDPReceiveBuffer.DeleteLabelValues(address), "an unknown receive buffer was exported as 0")
	require.False(t, quicUDPSendBuffer.DeleteLabelValues(address), "an unknown send buffer was exported as 0")
}
