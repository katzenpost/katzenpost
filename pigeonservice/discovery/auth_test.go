// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package discovery_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/nike/x25519"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/katzenpost/pigeonservice/common"
	"github.com/katzenpost/katzenpost/pigeonservice/discovery"
)

func keys(t *testing.T) (*common.ServiceKey, *common.PluginKey) {
	t.Helper()
	scheme := x25519.Scheme(rand.Reader)
	sp, ss, err := scheme.GenerateKeyPair()
	require.NoError(t, err)
	pp, pk, err := scheme.GenerateKeyPair()
	require.NoError(t, err)
	return &common.ServiceKey{Scheme: scheme, Public: sp, Private: ss},
		&common.PluginKey{Scheme: scheme, Public: pp, Private: pk}
}

func TestAdvertiseAndWithdrawMAC(t *testing.T) {
	svc, plugin := keys(t)
	a := &discovery.AdvertiseRequest{
		Descriptor: common.ServiceDescriptor{
			NIKEScheme: svc.Scheme.Name(),
			PublicKey:  svc.Public.Bytes(),
			Routers:    []common.RouterRef{{NodeIDHash: [32]byte{1}, Endpoint: "voucher_router"}},
		},
		Seq: 7,
	}
	require.NoError(t, discovery.SignAdvertise(svc, plugin.Public, a))
	require.NoError(t, discovery.VerifyAdvertise(plugin, a))
	a.Seq = 8
	require.ErrorIs(t, discovery.VerifyAdvertise(plugin, a), common.ErrBadMAC)

	w := &discovery.WithdrawRequest{ServiceID: svc.ID(), Seq: 9}
	require.NoError(t, discovery.SignWithdraw(svc, plugin.Public, w))
	require.NoError(t, discovery.VerifyWithdraw(plugin, svc.Public.Bytes(), w))
	other, _ := keys(t)
	require.ErrorIs(t, discovery.VerifyWithdraw(plugin, other.Public.Bytes(), w), common.ErrBadMAC)
}

func TestWireRoundTrip(t *testing.T) {
	d := common.ServiceDescriptor{NIKEScheme: "X25519-CTIDH1024", PublicKey: []byte{1, 2, 3},
		Routers: []common.RouterRef{{NodeIDHash: [32]byte{9}, Endpoint: "voucher_router"}}}
	req := &discovery.DirectoryRequest{Advertise: &discovery.AdvertiseRequest{Descriptor: d, Seq: 1, MAC: []byte{4}}}
	b, err := common.Marshal(req)
	require.NoError(t, err)
	var got discovery.DirectoryRequest
	require.NoError(t, common.Unmarshal(b, &got))
	require.Equal(t, req, &got)
	require.Nil(t, got.Lookup)
	require.Equal(t, d.ID(), common.IDFromPublicKey([]byte{1, 2, 3}))
}
