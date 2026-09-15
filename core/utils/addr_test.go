// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package utils

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEnsureURLAddrIPPort(t *testing.T) {
	cases := []struct {
		addr      string
		wantOK    bool
		wantSubst string // substring expected in error message when wantOK is false
	}{
		// Accept IPv4 literals across all recognised TCP schemes.
		{addr: "tcp://1.2.3.4:443", wantOK: true},
		{addr: "tcp4://1.2.3.4:443", wantOK: true},
		{addr: "tcp6://1.2.3.4:443", wantOK: true},
		{addr: "quic://1.2.3.4:443", wantOK: true},

		// Accept IPv6 literals (must be bracketed in URLs).
		{addr: "tcp://[::1]:443", wantOK: true},
		{addr: "tcp://[2001:db8::1]:443", wantOK: true},

		// Accept onion regardless of host shape; Tor handles resolution.
		{addr: "onion://abc123.onion:80", wantOK: true},
		{addr: "onion://6jcrz7jmczcsll4lad2uapetqlj5i6as74pig7s5ef3aroatcc6bolid.onion:65534", wantOK: true},

		// 0.0.0.0 and IPv6 unspecified are valid IP literals (bind addresses).
		{addr: "tcp://0.0.0.0:443", wantOK: true},
		{addr: "tcp://[::]:443", wantOK: true},

		// Reject DNS hostnames on every TCP-family scheme.
		{addr: "tcp://example.com:443", wantOK: false, wantSubst: "not an IP literal"},
		{addr: "tcp://auth2:30003", wantOK: false, wantSubst: "not an IP literal"},
		{addr: "tcp4://localhost:1984", wantOK: false, wantSubst: "not an IP literal"},
		{addr: "quic://gateway1.example:443", wantOK: false, wantSubst: "not an IP literal"},

		// Reject unrecognised schemes.
		{addr: "udp://1.2.3.4:443", wantOK: false, wantSubst: "unrecognised scheme"},
		{addr: "http://1.2.3.4:443", wantOK: false, wantSubst: "unrecognised scheme"},

		// Reject missing port.
		{addr: "tcp://1.2.3.4", wantOK: false, wantSubst: "no port"},

		// Reject malformed URLs.
		{addr: "not a url at all", wantOK: false},
	}
	for _, tc := range cases {
		t.Run(tc.addr, func(t *testing.T) {
			err := EnsureURLAddrIPPort(tc.addr)
			if tc.wantOK {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			if tc.wantSubst != "" {
				require.Contains(t, err.Error(), tc.wantSubst)
			}
		})
	}
}

func TestRejectDNSAddrs(t *testing.T) {
	good := []string{"tcp://1.2.3.4:443", "tcp://[::1]:443", "onion://x.onion:80"}
	mixed := []string{"tcp://1.2.3.4:443", "tcp://example.com:443"}

	// allowHostnames=true short-circuits: even bad addresses pass.
	require.NoError(t, RejectDNSAddrs(mixed, true))

	// allowHostnames=false: clean slice OK, dirty slice rejected.
	require.NoError(t, RejectDNSAddrs(good, false))
	require.Error(t, RejectDNSAddrs(mixed, false))
}

func TestRejectDNSMetricsAddr(t *testing.T) {
	// Empty MetricsAddress is permitted (signals "no listener").
	require.NoError(t, RejectDNSMetricsAddr("", false))

	// IP literals accepted.
	require.NoError(t, RejectDNSMetricsAddr("127.0.0.1:6543", false))
	require.NoError(t, RejectDNSMetricsAddr("[::1]:6543", false))

	// Hostnames rejected when allowHostnames is false.
	require.Error(t, RejectDNSMetricsAddr("metrics-host:6543", false))
	require.Error(t, RejectDNSMetricsAddr("auth1:6543", false))

	// Hostnames accepted when allowHostnames is true.
	require.NoError(t, RejectDNSMetricsAddr("auth1:6543", true))

	// Missing port rejected.
	require.Error(t, RejectDNSMetricsAddr("127.0.0.1", false))
}
