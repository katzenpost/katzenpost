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

func TestListenAddressIsAFlag(t *testing.T) {
	flags := newRootCommand().Flags()
	listen := flags.Lookup("listen")
	require.NotNil(t, listen, "no --listen flag")
	require.Equal(t, "127.0.0.1:8080", listen.DefValue)
	port := flags.Lookup("port")
	require.NotNil(t, port)
	require.NotEmpty(t, port.Deprecated, "--port not deprecated in favour of --listen")
}
