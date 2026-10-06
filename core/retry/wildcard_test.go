// SPDX-License-Identifier: AGPL-3.0-only

package retry

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFilterByLocalAddressesWildcardListenerIsDualStack(t *testing.T) {
	if runtime.GOOS == "openbsd" || runtime.GOOS == "dragonfly" {
		t.Skip("wildcard listeners are single-family on this OS")
	}
	peer := []string{"tcp://192.0.2.1:29483", "tcp://[2001:db8::1]:29483"}
	require.Equal(t, peer, FilterByLocalAddresses([]string{"tcp://[::]:29483"}, peer))
	require.Equal(t, peer, FilterByLocalAddresses([]string{"tcp://0.0.0.0:29483"}, peer))
	require.Equal(t, peer, FilterByLocalAddresses([]string{"quic://[::]:29483"}, peer))
}

func TestFilterByLocalAddressesSingleFamilyWildcard(t *testing.T) {
	peer := []string{"tcp://192.0.2.1:29483", "tcp://[2001:db8::1]:29483"}
	require.Equal(t, peer[:1], FilterByLocalAddresses([]string{"tcp4://0.0.0.0:29483"}, peer))
	require.Equal(t, peer[1:], FilterByLocalAddresses([]string{"tcp6://[::]:29483"}, peer))
}
