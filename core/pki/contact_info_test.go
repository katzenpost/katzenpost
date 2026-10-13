// SPDX-License-Identifier: AGPL-3.0-only

package pki

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const contactGoldenMix = "ad644e616d65646d6978316545706f636807674c696e6b4b65794103674d69784b657973a10741046756657273696f6e6069416464726573736573a16374637081717463703a2f2f3132372e302e302e313a31694b6165747a6368656ef66a4c6f6164576569676874006b4964656e746974794b65794201026d4973476174657761794e6f6465f46d4973536572766963654e6f6465f47241757468656e7469636174696f6e5479706560774b6165747a6368656e416476657274697a656444617461f6"

func contactGoldenDescriptor() *MixDescriptor {
	return &MixDescriptor{Name: "mix1", Epoch: 7, IdentityKey: []byte{1, 2}, LinkKey: []byte{3}, MixKeys: map[uint64][]byte{7: {4}}, Addresses: map[string][]string{"tcp": {"tcp://127.0.0.1:1"}}}
}

func TestContactInfoEmptyKeepsEncoding(t *testing.T) {
	b, err := contactGoldenDescriptor().MarshalBinary()
	require.NoError(t, err)
	require.Equal(t, contactGoldenMix, hex.EncodeToString(b))
}

func TestContactInfoRoundTrip(t *testing.T) {
	m := contactGoldenDescriptor()
	m.ContactInfo = "ops@example.org"
	b, err := m.MarshalBinary()
	require.NoError(t, err)
	require.NotEqual(t, contactGoldenMix, hex.EncodeToString(b))
	got := new(MixDescriptor)
	require.NoError(t, got.UnmarshalBinary(b))
	require.Equal(t, m, got)
}

func TestIsContactInfoWellFormed(t *testing.T) {
	for _, v := range []string{"", "ops@example.org", "Jane <ops@example.org> https://example.org/pgp.asc ~!", strings.Repeat("x", 256)} {
		require.NoError(t, IsContactInfoWellFormed(v), "%q", v)
	}
	for _, v := range []string{strings.Repeat("x", 257), "a\nb", "a\x00", "a\x7f", "caf\xc3\xa9", "\t"} {
		require.Error(t, IsContactInfoWellFormed(v), "%q", v)
	}
}
