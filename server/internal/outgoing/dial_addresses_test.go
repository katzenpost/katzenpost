// SPDX-License-Identifier: AGPL-3.0-only

package outgoing

import (
	"testing"

	"github.com/stretchr/testify/require"

	cpki "github.com/katzenpost/katzenpost/core/pki"
)

func TestDialAddressesFiltersByLocalFamilies(t *testing.T) {
	desc := &cpki.MixDescriptor{Addresses: map[string][]string{
		cpki.TransportTCPv4: {"tcp4://192.0.2.1:4242"},
		cpki.TransportTCPv6: {"tcp6://[2001:db8::1]:4242"},
	}}
	require.Equal(t, []string{"tcp4://192.0.2.1:4242"}, dialAddresses([]string{"tcp://198.51.100.7:1234"}, desc))
	require.Equal(t, []string{"tcp6://[2001:db8::1]:4242"}, dialAddresses([]string{"tcp://[2001:db8::7]:1234"}, desc))
	require.Equal(t, []string{"tcp4://192.0.2.1:4242", "tcp6://[2001:db8::1]:4242"}, dialAddresses(nil, desc))
}

func TestDialAddressesKeepsAllWhenNoneMatch(t *testing.T) {
	desc := &cpki.MixDescriptor{Addresses: map[string][]string{
		cpki.TransportTCPv6: {"tcp6://[2001:db8::1]:4242"},
	}}
	require.Equal(t, []string{"tcp6://[2001:db8::1]:4242"}, dialAddresses([]string{"tcp://198.51.100.7:1234"}, desc))
}
