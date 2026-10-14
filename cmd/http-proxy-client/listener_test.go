// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestListenerIsLocalAndBounded(t *testing.T) {
	srv := newHTTPServer(proxyClientConfig{port: 8080}, nil)
	host, _, err := net.SplitHostPort(srv.Addr)
	require.NoError(t, err)
	ip := net.ParseIP(host)
	require.Truef(t, ip != nil && ip.IsLoopback(), "client listens on %q, reachable from every interface", srv.Addr)
	require.Positivef(t, srv.ReadHeaderTimeout, "client waits forever for request headers")
	require.Positive(t, srv.IdleTimeout)
}

func TestDefaultLogLevelIsNotDebug(t *testing.T) {
	require.NotEqual(t, "DEBUG", newRootCommand().Flags().Lookup("log_level").DefValue)
}
