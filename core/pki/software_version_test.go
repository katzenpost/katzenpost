// SPDX-License-Identifier: AGPL-3.0-only

package pki

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	goldenMix     = "ad644e616d65646d6978316545706f636807674c696e6b4b65794103674d69784b657973a10741046756657273696f6e6069416464726573736573a16374637081717463703a2f2f3132372e302e302e313a31694b6165747a6368656ef66a4c6f6164576569676874006b4964656e746974794b65794201026d4973476174657761794e6f6465f46d4973536572766963654e6f6465f47241757468656e7469636174696f6e5479706560774b6165747a6368656e416476657274697a656444617461f6"
	goldenReplica = "a7644e616d656272316545706f636807674c696e6b4b6579410369416464726573736573a16374637081717463703a2f2f3132372e302e302e313a32695265706c6963614944026b4964656e746974794b65794201026c456e76656c6f70654b657973a1014105"
)

func goldenDescriptors() (*MixDescriptor, *ReplicaDescriptor) {
	m := &MixDescriptor{Name: "mix1", Epoch: 7, IdentityKey: []byte{1, 2}, LinkKey: []byte{3}, MixKeys: map[uint64][]byte{7: {4}}, Addresses: map[string][]string{"tcp": {"tcp://127.0.0.1:1"}}}
	r := &ReplicaDescriptor{Name: "r1", ReplicaID: 2, Epoch: 7, IdentityKey: []byte{1, 2}, LinkKey: []byte{3}, EnvelopeKeys: map[uint64][]byte{1: {5}}, Addresses: map[string][]string{"tcp": {"tcp://127.0.0.1:2"}}}
	return m, r
}

func TestSoftwareVersionEmptyKeepsEncoding(t *testing.T) {
	m, r := goldenDescriptors()
	b, err := m.MarshalBinary()
	require.NoError(t, err)
	require.Equal(t, goldenMix, hex.EncodeToString(b))
	b, err = r.Marshal()
	require.NoError(t, err)
	require.Equal(t, goldenReplica, hex.EncodeToString(b))
}

func TestSoftwareVersionRoundTrip(t *testing.T) {
	m, r := goldenDescriptors()
	m.SoftwareVersion = "v0.0.73"
	r.SoftwareVersion = "v0.0.73"

	b, err := m.MarshalBinary()
	require.NoError(t, err)
	require.NotEqual(t, goldenMix, hex.EncodeToString(b))
	gotMix := new(MixDescriptor)
	require.NoError(t, gotMix.UnmarshalBinary(b))
	require.Equal(t, m, gotMix)

	b, err = r.Marshal()
	require.NoError(t, err)
	require.NotEqual(t, goldenReplica, hex.EncodeToString(b))
	gotReplica := new(ReplicaDescriptor)
	require.NoError(t, gotReplica.Unmarshal(b))
	require.Equal(t, r, gotReplica)
}

func TestIsSoftwareVersionWellFormed(t *testing.T) {
	for _, v := range []string{"", "v0.0.73", "katzenpost v0.0.73-rc1 (abc123) ~!", strings.Repeat("x", 128)} {
		require.NoError(t, IsSoftwareVersionWellFormed(v), "%q", v)
	}
	for _, v := range []string{strings.Repeat("x", 129), "v1\n", "v1\x00", "v1\x7f", "v\xc3\xa91", "\t"} {
		require.Error(t, IsSoftwareVersionWellFormed(v), "%q", v)
	}
}
