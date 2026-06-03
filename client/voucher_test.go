// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package client

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/client/thin"
	"github.com/katzenpost/katzenpost/core/log"
)

// newVoucherTestDaemon builds a minimal daemon with a registered mock
// connection, mirroring TestDaemonNewKeypair_Success. The returned channel
// receives one Response per handler call.
func newVoucherTestDaemon(t *testing.T) (*Daemon, *[AppIDLength]byte, chan *Response) {
	t.Helper()
	logBackend, err := log.New("", "debug", false)
	require.NoError(t, err)

	cfg, err := config.LoadFile("testdata/client.toml")
	require.NoError(t, err)
	port, err := getFreePort()
	require.NoError(t, err)
	cfg.Listen.Tcp.Address = fmt.Sprintf("127.0.0.1:%d", port)

	client := &Client{cfg: cfg}
	rates := &Rates{}
	egressCh := make(chan *Request, 10)
	listener, err := NewListener(client, rates, egressCh, logBackend, nil)
	require.NoError(t, err)
	t.Cleanup(listener.Shutdown)

	d := &Daemon{
		logbackend: logBackend,
		log:        logBackend.GetLogger("test"),
		listener:   listener,
	}

	appID := &[AppIDLength]byte{}
	copy(appID[:], []byte("test-app-voucher"))
	responseCh := make(chan *Response, 1)
	mockConn := &mockIncomingConn{appID: appID, responseCh: responseCh}
	listener.connsLock.Lock()
	listener.conns[*appID] = mockConn.toIncomingConn(listener, logBackend)
	listener.connsLock.Unlock()
	return d, appID, responseCh
}

func awaitResponse(t *testing.T, responseCh chan *Response) *Response {
	t.Helper()
	select {
	case resp := <-responseCh:
		return resp
	case <-time.After(time.Second):
		t.Fatal("expected a response but got none within timeout")
		return nil
	}
}

func bobWriteCapBytes(t *testing.T) []byte {
	t.Helper()
	wc, err := bacap.NewWriteCap(rand.Reader)
	require.NoError(t, err)
	b, err := wc.MarshalBinary()
	require.NoError(t, err)
	return b
}

func TestDaemonVoucherRoundTrip(t *testing.T) {
	d, appID, responseCh := newVoucherTestDaemon(t)
	bob := bobWriteCapBytes(t)
	whoReply := []byte("opaque-group-membership-blob")

	// Mint.
	d.voucherMint(&Request{AppID: appID, VoucherMint: &thin.VoucherMint{
		MessageWriteCap: bob, DisplayName: "bob",
	}})
	mint := awaitResponse(t, responseCh).VoucherMintReply
	require.NotNil(t, mint)
	require.Equal(t, thin.ThinClientSuccess, mint.ErrorCode)
	require.NotEmpty(t, mint.Voucher)
	require.NotEmpty(t, mint.VoucherPayload)
	require.NotEmpty(t, mint.VoucherSecretKey)
	require.NotEmpty(t, mint.VoucherPublicKey)

	// DeriveStream agrees with mint.
	d.voucherDeriveStream(&Request{AppID: appID, VoucherDeriveStream: &thin.VoucherDeriveStream{
		Voucher: mint.Voucher,
	}})
	derive := awaitResponse(t, responseCh).VoucherDeriveStreamReply
	require.NotNil(t, derive)
	require.Equal(t, mint.VoucherWriteCap, derive.VoucherWriteCap)
	require.Equal(t, mint.VoucherReadCap, derive.VoucherReadCap)

	// Induct.
	d.voucherInduct(&Request{AppID: appID, VoucherInduct: &thin.VoucherInduct{
		Voucher: mint.Voucher, VoucherPayload: mint.VoucherPayload, WhoReply: whoReply,
	}})
	induct := awaitResponse(t, responseCh).VoucherInductReply
	require.NotNil(t, induct)
	require.Equal(t, thin.ThinClientSuccess, induct.ErrorCode)
	require.Equal(t, "bob", induct.DisplayName)
	require.NotEmpty(t, induct.SealedReply)
	require.NotEmpty(t, induct.MutatedMessageReadCap)
	require.Equal(t, mint.VoucherWriteCap, induct.VoucherWriteCap)

	// Open.
	d.voucherOpen(&Request{AppID: appID, VoucherOpen: &thin.VoucherOpen{
		VoucherSecretKey: mint.VoucherSecretKey, SealedReply: induct.SealedReply, MessageWriteCap: bob,
	}})
	open := awaitResponse(t, responseCh).VoucherOpenReply
	require.NotNil(t, open)
	require.Equal(t, thin.ThinClientSuccess, open.ErrorCode)
	require.Equal(t, whoReply, open.WhoReply)
	require.Equal(t, induct.Salt, open.Salt)
	require.NotEmpty(t, open.MutatedMessageWriteCap)

	// The crux: the joiner's salt-mutated write cap and the inductor's
	// salt-mutated read cap address the same box sequence.
	mutatedWC, err := bacap.NewWriteCapFromBytes(open.MutatedMessageWriteCap)
	require.NoError(t, err)
	rcBytes, err := mutatedWC.ReadCap().MarshalBinary()
	require.NoError(t, err)
	require.Equal(t, induct.MutatedMessageReadCap, rcBytes)
}

func TestDaemonVoucherInduct_HashMismatch(t *testing.T) {
	d, appID, responseCh := newVoucherTestDaemon(t)
	bob := bobWriteCapBytes(t)
	d.voucherMint(&Request{AppID: appID, VoucherMint: &thin.VoucherMint{
		MessageWriteCap: bob, DisplayName: "bob",
	}})
	mint := awaitResponse(t, responseCh).VoucherMintReply

	tampered := append([]byte(nil), mint.VoucherPayload...)
	tampered[0] ^= 0xFF
	d.voucherInduct(&Request{AppID: appID, VoucherInduct: &thin.VoucherInduct{
		Voucher: mint.Voucher, VoucherPayload: tampered, WhoReply: []byte("x"),
	}})
	resp := awaitResponse(t, responseCh)
	require.NotNil(t, resp.VoucherInductReply)
	require.Equal(t, thin.ThinClientErrorVoucherHashMismatch, resp.VoucherInductReply.ErrorCode)
}

func TestDaemonVoucherOpen_WrongKey(t *testing.T) {
	d, appID, responseCh := newVoucherTestDaemon(t)
	bob := bobWriteCapBytes(t)

	d.voucherMint(&Request{AppID: appID, VoucherMint: &thin.VoucherMint{
		MessageWriteCap: bob, DisplayName: "alice",
	}})
	mintA := awaitResponse(t, responseCh).VoucherMintReply
	d.voucherMint(&Request{AppID: appID, VoucherMint: &thin.VoucherMint{
		MessageWriteCap: bobWriteCapBytes(t), DisplayName: "bob",
	}})
	mintB := awaitResponse(t, responseCh).VoucherMintReply

	d.voucherInduct(&Request{AppID: appID, VoucherInduct: &thin.VoucherInduct{
		Voucher: mintA.Voucher, VoucherPayload: mintA.VoucherPayload, WhoReply: []byte("x"),
	}})
	induct := awaitResponse(t, responseCh).VoucherInductReply

	d.voucherOpen(&Request{AppID: appID, VoucherOpen: &thin.VoucherOpen{
		VoucherSecretKey: mintB.VoucherSecretKey, SealedReply: induct.SealedReply, MessageWriteCap: bob,
	}})
	resp := awaitResponse(t, responseCh)
	require.NotNil(t, resp.VoucherOpenReply)
	require.Equal(t, thin.ThinClientErrorVoucherSealOpenFailed, resp.VoucherOpenReply.ErrorCode)
}
