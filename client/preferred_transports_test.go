// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package client

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/client/thin"
)

func TestDaemonSetPreferredTransports(t *testing.T) {
	d, appID, responseCh := newVoucherTestDaemon(t)
	d.client = &Client{cfg: d.listener.client.cfg}
	d.client.cfg.PreferedTransports = []string{"tcp"}

	set := func(transports []string) uint8 {
		t.Helper()
		queryID := &[thin.QueryIDLength]byte{7}
		req := &Request{AppID: appID, SetPreferredTransports: &thin.SetPreferredTransports{QueryID: queryID, Transports: transports}}
		require.True(t, isLocalRequest(req), "SetPreferredTransports issues no Sphinx send")
		d.dispatchLocal(req)
		resp := awaitResponse(t, responseCh)
		require.NotNil(t, resp.SetPreferredTransportsReply)
		require.Equal(t, queryID, resp.SetPreferredTransportsReply.QueryID)
		return resp.SetPreferredTransportsReply.ErrorCode
	}

	require.Equal(t, thin.ThinClientSuccess, set([]string{"quic", "tcp"}))
	require.Equal(t, []string{"quic", "tcp"}, d.client.PreferredTransports())
	require.Equal(t, thin.ThinClientErrorInvalidRequest, set([]string{"udp"}))
	require.Equal(t, thin.ThinClientErrorInvalidRequest, set([]string{"quic", "quic"}))
	require.Equal(t, []string{"quic", "tcp"}, d.client.PreferredTransports(), "a refused request must leave the order alone")
	require.Equal(t, thin.ThinClientSuccess, set(nil))
	require.Equal(t, []string{"tcp"}, d.client.PreferredTransports(), "an empty order must restore the configured one")
}
