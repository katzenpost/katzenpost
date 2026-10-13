// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"context"
	"io"
	"net"
	"net/url"
	"testing"
	"time"

	signschemes "github.com/katzenpost/hpqc/sign/schemes"
	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"
)

const testIdentityScheme = "Ed25519 Sphincs+"

func TestStatelessResetKeyFollowsTheIdentityKey(t *testing.T) {
	scheme := signschemes.ByName(testIdentityScheme)
	_, identityPrivateKey, err := scheme.GenerateKey()
	require.NoError(t, err)
	_, otherIdentityPrivateKey, err := scheme.GenerateKey()
	require.NoError(t, err)

	resetKey, err := statelessResetKey(identityPrivateKey)
	require.NoError(t, err)
	again, err := statelessResetKey(identityPrivateKey)
	require.NoError(t, err)
	other, err := statelessResetKey(otherIdentityPrivateKey)
	require.NoError(t, err)
	require.Equal(t, *resetKey, *again)
	require.NotEqual(t, *resetKey, *other)

	identitySecret, err := identityPrivateKey.MarshalBinary()
	require.NoError(t, err)
	require.NotEqual(t, identitySecret[:len(resetKey)], resetKey[:])
}

func TestListenReleasesItsSocketAfterTheLastConnection(t *testing.T) {
	_, identityPrivateKey, err := signschemes.ByName(testIdentityScheme).GenerateKey()
	require.NoError(t, err)
	l, err := ListenWithEpochKeys("127.0.0.1:0", identityPrivateKey, newTestEpochKeys(t, t.TempDir(), newEpochClock(CurrentEpoch())), nil)
	require.NoError(t, err)
	addr := l.Addr().String()
	u, err := url.Parse("quic://" + addr)
	require.NoError(t, err)
	client, err := DialURL(u, context.Background(), nil, nil, nil)
	require.NoError(t, err)
	defer client.Close()
	_, err = client.Write([]byte{1})
	require.NoError(t, err)
	server, err := l.Accept()
	require.NoError(t, err)
	var b [1]byte
	_, err = io.ReadFull(server, b[:])
	require.NoError(t, err)

	require.NoError(t, l.Close())
	_, err = client.Write([]byte{2})
	require.NoError(t, err)
	_, err = io.ReadFull(server, b[:])
	require.NoError(t, err, "closing the listener must keep its accepted connections")
	require.Equal(t, byte(2), b[0])
	_, err = net.ListenPacket("udp", addr)
	require.Error(t, err, "the socket was released while a connection still used it")

	require.NoError(t, server.Close())
	require.Eventually(t, func() bool {
		pc, err := net.ListenPacket("udp", addr)
		if err != nil {
			return false
		}
		pc.Close()
		return true
	}, closeLinger+2*time.Second, 50*time.Millisecond, "the socket outlived the listener and its connections")
}

func TestListenWithTheSameKeyResetsConnectionsOfACrashedListener(t *testing.T) {
	_, identityPrivateKey, err := signschemes.ByName(testIdentityScheme).GenerateKey()
	require.NoError(t, err)
	keys := newTestEpochKeys(t, t.TempDir(), newEpochClock(CurrentEpoch()))
	crashed, err := ListenWithEpochKeys("127.0.0.1:0", identityPrivateKey, keys, nil)
	require.NoError(t, err)
	addr := crashed.Addr().String()
	u, err := url.Parse("quic://" + addr)
	require.NoError(t, err)
	client, err := DialURL(u, context.Background(), nil, nil, nil)
	require.NoError(t, err)
	defer client.Close()
	_, err = client.Write([]byte{1})
	require.NoError(t, err)
	server, err := crashed.Accept()
	require.NoError(t, err)
	var b [1]byte
	_, err = io.ReadFull(server, b[:])
	require.NoError(t, err)
	require.NoError(t, crashed.transport.Conn.Close())

	restarted, err := ListenWithEpochKeys(addr, identityPrivateKey, keys, nil)
	require.NoError(t, err)
	defer restarted.Close()
	_, err = client.Write(make([]byte, 512))
	require.NoError(t, err)
	qc := client.(*QuicConn)
	select {
	case <-qc.Conn.Context().Done():
		var reset *quic.StatelessResetError
		require.ErrorAs(t, context.Cause(qc.Conn.Context()), &reset)
	case <-time.After(5 * time.Second):
		t.Fatal("the connection to the crashed listener was still open 5s after the restart")
	}
}
