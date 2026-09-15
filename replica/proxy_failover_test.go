// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/pki"
)

func TestProxyShardOrder(t *testing.T) {
	t.Parallel()

	a := &pki.ReplicaDescriptor{Name: "a"}
	b := &pki.ReplicaDescriptor{Name: "b"}
	c := &pki.ReplicaDescriptor{Name: "c"}

	require.Equal(t, []*pki.ReplicaDescriptor{a, b}, proxyShardOrder([]*pki.ReplicaDescriptor{a, b}, 0))
	require.Equal(t, []*pki.ReplicaDescriptor{b, a}, proxyShardOrder([]*pki.ReplicaDescriptor{a, b}, 1))
	require.Equal(t, []*pki.ReplicaDescriptor{a}, proxyShardOrder([]*pki.ReplicaDescriptor{a}, 0))
	require.Equal(t, []*pki.ReplicaDescriptor{b, a, c}, proxyShardOrder([]*pki.ReplicaDescriptor{a, b, c}, 1))
}
