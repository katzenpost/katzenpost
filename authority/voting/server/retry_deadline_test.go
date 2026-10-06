// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"
	kemschemes "github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/rand"
	signschemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/core/wire/commands"
)

func retryTestSender(t *testing.T) *state {
	sender, _, _ := mkAuthState(t, "sender", "Xwing")
	sender.hasIPv4 = true
	sender.s.cfg.Server.PersistentPeerConns = false
	sender.s.cfg.Server.PeerRetryBaseDelay = 5 * time.Millisecond
	sender.s.cfg.Server.PeerRetryMaxDelay = 20 * time.Millisecond
	return sender
}

func certResponder(t *testing.T, sender *state, codes func(n int32) uint8) (*int32, *config.Authority) {
	_, respID, respLink := mkAuthState(t, "responder", "Xwing")
	rh := hash.Sum256From(respID)
	sender.authorizedAuthorities[rh] = true
	respCfg := &wire.SessionConfig{
		KEMScheme:          kemschemes.ByName("Xwing"),
		PKISignatureScheme: signschemes.ByName("Ed25519"),
		Authenticator:      acceptAuthenticator{},
		AdditionalData:     rh[:],
		AuthenticationKey:  respLink,
		RandomReader:       rand.Reader,
	}
	var n int32
	sender.dialContextFn = func(ctx context.Context, network, addr string) (net.Conn, error) {
		cli, srv := net.Pipe()
		go func() {
			defer srv.Close()
			rs, err := wire.NewPKISession(respCfg, false)
			if err != nil {
				return
			}
			defer rs.Close()
			if err := rs.Initialize(context.Background(), srv); err != nil {
				return
			}
			for {
				cmd, err := rs.RecvCommand(context.Background())
				if err != nil {
					return
				}
				if _, ok := cmd.(*commands.Cert); !ok {
					return
				}
				code := codes(atomic.AddInt32(&n, 1))
				if err := rs.SendCommand(context.Background(), &commands.CertStatus{ErrorCode: code}); err != nil {
					return
				}
			}
		}()
		return cli, nil
	}
	peer := retryTestPeer()
	peer.IdentityPublicKey = respID
	peer.LinkPublicKey = config.LinkPublicKey{PublicKey: respLink.Public()}
	return &n, peer
}

func retryTestPeer() *config.Authority {
	return &config.Authority{Identifier: "responder", Addresses: []string{"tcp://127.0.0.1:1"}}
}

func retryTestCert(sender *state) *commands.Cert {
	return &commands.Cert{Epoch: 1, PublicKey: sender.s.identityPublicKey, Payload: []byte("cert")}
}

func TestSendToPeerRetriesTooEarly(t *testing.T) {
	sender := retryTestSender(t)
	n, peer := certResponder(t, sender, func(n int32) uint8 {
		if n <= 2 {
			return commands.CertTooEarly
		}
		return commands.CertOk
	})
	resp, err := sender.sendCommandToPeerWithDeadline(peer, retryTestCert(sender), time.Now().Add(10*time.Second))
	require.NoError(t, err)
	require.Equal(t, uint8(commands.CertOk), resp.(*commands.CertStatus).ErrorCode)
	require.Equal(t, int32(3), atomic.LoadInt32(n))
}

func TestSendToPeerTooEarlyUntilDeadline(t *testing.T) {
	sender := retryTestSender(t)
	n, peer := certResponder(t, sender, func(int32) uint8 { return commands.CertTooEarly })
	start := time.Now()
	resp, err := sender.sendCommandToPeerWithDeadline(peer, retryTestCert(sender), start.Add(300*time.Millisecond))
	require.NoError(t, err)
	require.Equal(t, uint8(commands.CertTooEarly), resp.(*commands.CertStatus).ErrorCode)
	require.Greater(t, atomic.LoadInt32(n), int32(1))
	require.GreaterOrEqual(t, time.Since(start), 250*time.Millisecond)
}

func TestSendToPeerTooLateNotRetried(t *testing.T) {
	sender := retryTestSender(t)
	n, peer := certResponder(t, sender, func(int32) uint8 { return commands.CertTooLate })
	resp, err := sender.sendCommandToPeerWithDeadline(peer, retryTestCert(sender), time.Now().Add(10*time.Second))
	require.NoError(t, err)
	require.Equal(t, uint8(commands.CertTooLate), resp.(*commands.CertStatus).ErrorCode)
	require.Equal(t, int32(1), atomic.LoadInt32(n))
}

func TestSendToPeerTransientRetriedUntilDeadline(t *testing.T) {
	sender := retryTestSender(t)
	var dials int32
	sender.dialContextFn = func(ctx context.Context, network, addr string) (net.Conn, error) {
		atomic.AddInt32(&dials, 1)
		return nil, errors.New("connection refused")
	}
	start := time.Now()
	_, err := sender.sendCommandToPeerWithDeadline(retryTestPeer(), retryTestCert(sender), start.Add(300*time.Millisecond))
	require.Error(t, err)
	require.Greater(t, atomic.LoadInt32(&dials), int32(3))
	require.GreaterOrEqual(t, time.Since(start), 250*time.Millisecond)
	require.Less(t, time.Since(start), 5*time.Second)
}

func TestSendToPeerPermanentNotRetried(t *testing.T) {
	sender := retryTestSender(t)
	var dials int32
	sender.dialContextFn = func(ctx context.Context, network, addr string) (net.Conn, error) {
		atomic.AddInt32(&dials, 1)
		return nil, errors.New("permission denied")
	}
	_, err := sender.sendCommandToPeerWithDeadline(retryTestPeer(), retryTestCert(sender), time.Now().Add(10*time.Second))
	require.Error(t, err)
	require.Equal(t, int32(1), atomic.LoadInt32(&dials))
}
