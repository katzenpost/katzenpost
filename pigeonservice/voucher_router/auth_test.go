// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package voucher_router_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/nike/x25519"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/katzenpost/pigeonservice/common"
	"github.com/katzenpost/katzenpost/pigeonservice/voucher_router"
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

func TestRegisterMAC(t *testing.T) {
	svc, plugin := keys(t)
	r := &voucher_router.RegisterRequest{NIKEScheme: svc.Scheme.Name(), PublicKey: svc.Public.Bytes(), Voucher: []byte("voucher")}
	require.NoError(t, voucher_router.SignRegister(svc, plugin.Public, r))
	require.NoError(t, voucher_router.VerifyRegister(plugin, r))

	tampered := *r
	tampered.Voucher = []byte("another")
	require.ErrorIs(t, voucher_router.VerifyRegister(plugin, &tampered), common.ErrBadMAC)

	other, _ := keys(t)
	forged := *r
	forged.PublicKey = other.Public.Bytes()
	require.ErrorIs(t, voucher_router.VerifyRegister(plugin, &forged), common.ErrBadMAC, "the MAC binds the service key")

	_, otherPlugin := keys(t)
	require.ErrorIs(t, voucher_router.VerifyRegister(otherPlugin, r), common.ErrBadMAC, "the MAC binds the plugin key")
}

func TestUnmarshalAcceptsZeroPaddingOnly(t *testing.T) {
	b, err := common.Marshal(&voucher_router.RouterReply{Status: common.StatusBusy})
	require.NoError(t, err)

	var r voucher_router.RouterReply
	require.NoError(t, common.Unmarshal(append(b, make([]byte, 2000)...), &r))
	require.Equal(t, common.StatusBusy, r.Status)

	require.ErrorIs(t, common.Unmarshal(append(b, 0, 0, 1), &r), common.ErrTrailingData)
}
