// SPDX-License-Identifier: AGPL-3.0-only

package pki

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func wellFormedDescriptor(epoch uint64) *MixDescriptor {
	return &MixDescriptor{
		Name:        "node",
		LinkKey:     []byte{1},
		IdentityKey: []byte{2},
		MixKeys:     map[uint64][]byte{epoch: {3}},
		Addresses:   map[string][]string{TransportTCPv4: {"tcp://127.0.0.1:1234"}},
	}
}

func TestDescriptorRejectsEmptyKeys(t *testing.T) {
	const epoch = 7
	require.NoError(t, IsDescriptorWellFormed(wellFormedDescriptor(epoch), epoch),
		"the baseline descriptor must be well formed")

	t.Run("empty but non-nil LinkKey", func(t *testing.T) {
		d := wellFormedDescriptor(epoch)
		d.LinkKey = []byte{}
		require.Error(t, IsDescriptorWellFormed(d, epoch))
	})

	t.Run("empty but non-nil IdentityKey", func(t *testing.T) {
		d := wellFormedDescriptor(epoch)
		d.IdentityKey = []byte{}
		require.Error(t, IsDescriptorWellFormed(d, epoch))
	})

	t.Run("empty but non-nil MixKey for the epoch", func(t *testing.T) {
		d := wellFormedDescriptor(epoch)
		d.MixKeys[epoch] = []byte{}
		require.Error(t, IsDescriptorWellFormed(d, epoch))
	})
}

func TestDescriptorRejectsContradictoryRoleFlags(t *testing.T) {
	const epoch = 7
	d := wellFormedDescriptor(epoch)
	d.IsGatewayNode = true
	d.IsServiceNode = true
	require.Error(t, IsDescriptorWellFormed(d, epoch))
}

func wellFormedReplica(epoch uint64) *ReplicaDescriptor {
	return &ReplicaDescriptor{
		Name:         "replica",
		LinkKey:      []byte{1},
		IdentityKey:  []byte{2},
		EnvelopeKeys: map[uint64][]byte{epoch: {3}},
		Addresses:    map[string][]string{TransportTCPv4: {"tcp://127.0.0.1:1234"}},
	}
}

func TestReplicaDescriptorRejectsEmptyKeys(t *testing.T) {
	const epoch = 7
	require.NoError(t, IsReplicaDescriptorWellFormed(wellFormedReplica(epoch), epoch),
		"the baseline replica descriptor must be well formed")

	t.Run("empty but non-nil LinkKey", func(t *testing.T) {
		d := wellFormedReplica(epoch)
		d.LinkKey = []byte{}
		require.Error(t, IsReplicaDescriptorWellFormed(d, epoch))
	})

	t.Run("empty but non-nil IdentityKey", func(t *testing.T) {
		d := wellFormedReplica(epoch)
		d.IdentityKey = []byte{}
		require.Error(t, IsReplicaDescriptorWellFormed(d, epoch))
	})

	t.Run("empty but non-nil EnvelopeKey", func(t *testing.T) {
		d := wellFormedReplica(epoch)
		d.EnvelopeKeys[epoch] = []byte{}
		require.Error(t, IsReplicaDescriptorWellFormed(d, epoch))
	})
}
