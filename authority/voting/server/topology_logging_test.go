// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/pki"
)

// documentRoleCounts sums the mixes across every topology layer and reports the
// gateway, service node, and replica counts, so the assembled-consensus log can
// be compared against the authorized counts logged at startup.
func TestDocumentRoleCounts(t *testing.T) {
	mix := func() *pki.MixDescriptor { return &pki.MixDescriptor{} }
	replica := func() *pki.ReplicaDescriptor { return &pki.ReplicaDescriptor{} }

	doc := &pki.Document{
		Topology: [][]*pki.MixDescriptor{
			{mix(), mix()},
			{mix()},
			{mix(), mix(), mix()},
		},
		GatewayNodes:    []*pki.MixDescriptor{mix()},
		ServiceNodes:    []*pki.MixDescriptor{mix(), mix()},
		StorageReplicas: []*pki.ReplicaDescriptor{replica(), replica(), replica(), replica()},
	}

	mixes, gateways, serviceNodes, replicas := documentRoleCounts(doc)
	require.Equal(t, 6, mixes, "mixes must be summed across all topology layers")
	require.Equal(t, 1, gateways)
	require.Equal(t, 2, serviceNodes)
	require.Equal(t, 4, replicas)
}

// An empty document reports zero for every role rather than panicking.
func TestDocumentRoleCountsEmpty(t *testing.T) {
	mixes, gateways, serviceNodes, replicas := documentRoleCounts(&pki.Document{})
	require.Equal(t, 0, mixes)
	require.Equal(t, 0, gateways)
	require.Equal(t, 0, serviceNodes)
	require.Equal(t, 0, replicas)
}
