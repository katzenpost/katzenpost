// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package pigeonservice_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/nike/x25519"
	"github.com/katzenpost/hpqc/rand"

	ps "github.com/katzenpost/katzenpost/pigeonservice"
)

func keys(t *testing.T) (*ps.ServiceKey, *ps.PluginKey) {
	t.Helper()
	scheme := x25519.Scheme(rand.Reader)
	sp, ss, err := scheme.GenerateKeyPair()
	require.NoError(t, err)
	pp, pk, err := scheme.GenerateKeyPair()
	require.NoError(t, err)
	return &ps.ServiceKey{Scheme: scheme, Public: sp, Private: ss},
		&ps.PluginKey{Scheme: scheme, Public: pp, Private: pk}
}

func TestRegisterMAC(t *testing.T) {
	svc, plugin := keys(t)
	r := &ps.RegisterRequest{NIKEScheme: svc.Scheme.Name(), PublicKey: svc.Public.Bytes(), Voucher: []byte("voucher")}
	require.NoError(t, svc.SignRegister(plugin.Public, r))
	require.NoError(t, plugin.VerifyRegister(r))

	tampered := *r
	tampered.Voucher = []byte("another")
	require.ErrorIs(t, plugin.VerifyRegister(&tampered), ps.ErrBadMAC)

	other, _ := keys(t)
	forged := *r
	forged.PublicKey = other.Public.Bytes()
	require.ErrorIs(t, plugin.VerifyRegister(&forged), ps.ErrBadMAC, "the MAC binds the service key")

	_, otherPlugin := keys(t)
	require.ErrorIs(t, otherPlugin.VerifyRegister(r), ps.ErrBadMAC, "the MAC binds the plugin key")
}

func TestAdvertiseAndWithdrawMAC(t *testing.T) {
	svc, plugin := keys(t)
	a := &ps.AdvertiseRequest{
		Descriptor: ps.ServiceDescriptor{
			NIKEScheme: svc.Scheme.Name(),
			PublicKey:  svc.Public.Bytes(),
			Routers:    []ps.RouterRef{{NodeIDHash: [32]byte{1}, Endpoint: "voucher_router"}},
		},
		Seq: 7,
	}
	require.NoError(t, svc.SignAdvertise(plugin.Public, a))
	require.NoError(t, plugin.VerifyAdvertise(a))
	a.Seq = 8
	require.ErrorIs(t, plugin.VerifyAdvertise(a), ps.ErrBadMAC)

	w := &ps.WithdrawRequest{ServiceID: svc.ID(), Seq: 9}
	require.NoError(t, svc.SignWithdraw(plugin.Public, w))
	require.NoError(t, plugin.VerifyWithdraw(svc.Public.Bytes(), w))
	other, _ := keys(t)
	require.ErrorIs(t, plugin.VerifyWithdraw(other.Public.Bytes(), w), ps.ErrBadMAC)
}

func TestWireRoundTrip(t *testing.T) {
	d := ps.ServiceDescriptor{NIKEScheme: "X25519-CTIDH1024", PublicKey: []byte{1, 2, 3},
		Routers: []ps.RouterRef{{NodeIDHash: [32]byte{9}, Endpoint: "voucher_router"}}}
	req := &ps.DirectoryRequest{Advertise: &ps.AdvertiseRequest{Descriptor: d, Seq: 1, MAC: []byte{4}}}
	b, err := ps.Marshal(req)
	require.NoError(t, err)
	var got ps.DirectoryRequest
	require.NoError(t, ps.Unmarshal(b, &got))
	require.Equal(t, req, &got)
	require.Nil(t, got.Lookup)
	require.Equal(t, d.ID(), ps.IDFromPublicKey([]byte{1, 2, 3}))
}

func TestUnmarshalAcceptsZeroPaddingOnly(t *testing.T) {
	b, err := ps.Marshal(&ps.RouterReply{Status: ps.StatusBusy})
	require.NoError(t, err)

	var r ps.RouterReply
	require.NoError(t, ps.Unmarshal(append(b, make([]byte, 2000)...), &r))
	require.Equal(t, ps.StatusBusy, r.Status)

	require.ErrorIs(t, ps.Unmarshal(append(b, 0, 0, 1), &r), ps.ErrTrailingData)
}
