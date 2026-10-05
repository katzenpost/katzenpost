// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNodeIdentityKeyFile(t *testing.T) {
	cases := []struct {
		name, file, pem, want string
		ok                    bool
	}{
		{"new", "a.pem", "", "a.pem", true},
		{"deprecated", "", "a.pem", "a.pem", true},
		{"both equal", "a.pem", "a.pem", "a.pem", true},
		{"both differ", "a.pem", "b.pem", "", false},
		{"neither", "", "", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			n := &Node{Identifier: "n", IdentityPublicKeyFile: c.file, IdentityPublicKeyPem: c.pem}
			r := &StorageReplicaNode{Identifier: "r", IdentityPublicKeyFile: c.file, IdentityPublicKeyPem: c.pem}
			if !c.ok {
				require.ErrorContains(t, n.validate(true), "IdentityPublicKeyFile")
				require.ErrorContains(t, r.validate(), "IdentityPublicKeyFile")
				return
			}
			require.NoError(t, n.validate(true))
			require.NoError(t, r.validate())
			require.Equal(t, c.want, n.KeyFile())
			require.Equal(t, c.want, r.KeyFile())
		})
	}
}

func TestDeprecatedIdentityPublicKeyPem(t *testing.T) {
	current := &Node{Identifier: "a", IdentityPublicKeyFile: "a.pem"}
	old := &Node{Identifier: "b", IdentityPublicKeyPem: "b.pem"}

	require.False(t, (&Config{Mixes: []*Node{current}}).DeprecatedIdentityPublicKeyPem())
	require.True(t, (&Config{Mixes: []*Node{current, old}}).DeprecatedIdentityPublicKeyPem())
	require.True(t, (&Config{GatewayNodes: []*Node{old}}).DeprecatedIdentityPublicKeyPem())
	require.True(t, (&Config{ServiceNodes: []*Node{old}}).DeprecatedIdentityPublicKeyPem())
	require.True(t, (&Config{StorageReplicas: []*StorageReplicaNode{{Identifier: "r", IdentityPublicKeyPem: "r.pem"}}}).DeprecatedIdentityPublicKeyPem())
	require.True(t, (&Config{Topology: &Topology{Layers: []Layer{{Nodes: []Node{*old}}}}}).DeprecatedIdentityPublicKeyPem())
	require.False(t, (&Config{Topology: &Topology{Layers: []Layer{{Nodes: []Node{*current}}}}}).DeprecatedIdentityPublicKeyPem())
}
