// SPDX-License-Identifier: AGPL-3.0-only

package retry

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFilterByLocalAddresses(t *testing.T) {
	peer := []string{"tcp://192.0.2.1:29483", "tcp://[2001:db8::1]:29483", "quic://[2001:db8::1]:29483", "tcp://example.onion:29483"}
	v6 := []string{"tcp://[2001:db8::1]:29483", "quic://[2001:db8::2]:29483"}

	require.Equal(t,
		[]string{"tcp://192.0.2.1:29483", "tcp://example.onion:29483"},
		FilterByLocalAddresses([]string{"tcp://198.51.100.7:29483"}, peer))
	require.Equal(t,
		[]string{"tcp://[2001:db8::1]:29483", "quic://[2001:db8::1]:29483", "tcp://example.onion:29483"},
		FilterByLocalAddresses([]string{"tcp://[2001:db8::7]:29483"}, peer))
	require.Equal(t, peer, FilterByLocalAddresses([]string{"tcp://198.51.100.7:1", "tcp://[2001:db8::7]:1"}, peer))
	require.Equal(t, v6, FilterByLocalAddresses([]string{"tcp://198.51.100.7:29483"}, v6))
	require.Equal(t, peer, FilterByLocalAddresses(nil, peer))
	require.Equal(t, peer, FilterByLocalAddresses([]string{"tcp://mix.example.org:29483"}, peer))
}
