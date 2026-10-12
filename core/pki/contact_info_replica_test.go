// SPDX-License-Identifier: AGPL-3.0-only

package pki

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

const contactGoldenReplica = "a7644e616d65687265706c696361316545706f636807674c696e6b4b6579410369416464726573736573a16374637081717463703a2f2f3132372e302e302e313a31695265706c6963614944016b4964656e746974794b65794201026c456e76656c6f70654b657973a1014104"

func contactGoldenReplicaDescriptor() *ReplicaDescriptor {
	return &ReplicaDescriptor{Name: "replica1", ReplicaID: 1, Epoch: 7, IdentityKey: []byte{1, 2}, LinkKey: []byte{3}, EnvelopeKeys: map[uint64][]byte{1: {4}}, Addresses: map[string][]string{"tcp": {"tcp://127.0.0.1:1"}}}
}

func TestReplicaContactInfoEmptyKeepsEncoding(t *testing.T) {
	b, err := contactGoldenReplicaDescriptor().Marshal()
	require.NoError(t, err)
	require.Equal(t, contactGoldenReplica, hex.EncodeToString(b))
}

func TestReplicaContactInfoRoundTrip(t *testing.T) {
	r := contactGoldenReplicaDescriptor()
	r.ContactInfo = "ops@example.org"
	b, err := r.Marshal()
	require.NoError(t, err)
	require.NotEqual(t, contactGoldenReplica, hex.EncodeToString(b))
	got := new(ReplicaDescriptor)
	require.NoError(t, got.Unmarshal(b))
	require.Equal(t, r, got)
}
