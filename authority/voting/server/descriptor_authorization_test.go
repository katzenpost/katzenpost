// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"

	"github.com/katzenpost/katzenpost/core/pki"
)

// The descriptor authorization errors must name both the value the authority
// pins and the value the descriptor announces, on one line, so that an
// operator can diagnose a rejection without correlating separate log entries.
func TestReplicaAuthorizationError(t *testing.T) {
	idKey := []byte("storagereplica1-identity-key")
	st := &state{
		authorizedReplicaNodes: map[[publicKeyHashSize]byte]*authorizedReplicaInfo{
			hash.Sum256(idKey): {Identifier: "storagereplica1", ReplicaID: 1},
		},
	}

	require.NoError(t, st.replicaAuthorizationError(&pki.ReplicaDescriptor{
		Name: "storagereplica1", ReplicaID: 1, IdentityKey: idKey,
	}))

	t.Run("ReplicaID mismatch names both values", func(t *testing.T) {
		err := st.replicaAuthorizationError(&pki.ReplicaDescriptor{
			Name: "storagereplica1", ReplicaID: 0, IdentityKey: idKey,
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "ReplicaID mismatch")
		require.Contains(t, err.Error(), "ReplicaID=1")     // pinned
		require.Contains(t, err.Error(), "ReplicaID=0")     // announced
		require.Contains(t, err.Error(), "storagereplica1") // node name
	})

	t.Run("name mismatch", func(t *testing.T) {
		err := st.replicaAuthorizationError(&pki.ReplicaDescriptor{
			Name: "impostor", ReplicaID: 1, IdentityKey: idKey,
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "name mismatch")
		require.Contains(t, err.Error(), "storagereplica1")
		require.Contains(t, err.Error(), "impostor")
	})

	t.Run("identity key not pinned", func(t *testing.T) {
		err := st.replicaAuthorizationError(&pki.ReplicaDescriptor{
			Name: "storagereplica1", ReplicaID: 1, IdentityKey: []byte("unknown-key"),
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "not pinned")
	})
}

func TestDescriptorAuthorizationError(t *testing.T) {
	mixKey := []byte("mix1-identity-key")
	st := &state{
		authorizedMixes: map[[publicKeyHashSize]byte]string{
			hash.Sum256(mixKey): "mix1",
		},
	}

	require.NoError(t, st.descriptorAuthorizationError(&pki.MixDescriptor{
		Name: "mix1", IdentityKey: mixKey,
	}))

	err := st.descriptorAuthorizationError(&pki.MixDescriptor{
		Name: "wrong", IdentityKey: mixKey,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "name mismatch")
	require.Contains(t, err.Error(), "mix")

	err = st.descriptorAuthorizationError(&pki.MixDescriptor{
		Name: "ghost", IdentityKey: []byte("unknown-key"),
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not pinned")

	// A descriptor cannot be both a gateway and a service node.
	err = st.descriptorAuthorizationError(&pki.MixDescriptor{
		Name: "twofaced", IdentityKey: mixKey, IsGatewayNode: true, IsServiceNode: true,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "contradictory")
	require.Contains(t, err.Error(), "twofaced")
}
