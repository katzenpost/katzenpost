// SPDX-License-Identifier: AGPL-3.0-only

package transport

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWebsocketListenerSetsReadHeaderTimeout(t *testing.T) {
	ln, err := (&WsListenConfig{Address: "ws://127.0.0.1:0"}).Listen()
	require.NoError(t, err)
	defer ln.Close()

	wl, ok := ln.(*WebsocketListener)
	require.True(t, ok)
	require.NotZero(t, wl.server.ReadHeaderTimeout, "http.Server must bound how long a peer can take to send request headers")
}
