// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"context"
	"io"
	"net/url"
	"testing"
	"time"

	signschemes "github.com/katzenpost/hpqc/sign/schemes"
	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"
)

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

func TestListenAgainOnTheSamePortAfterClose(t *testing.T) {
	_, identityPrivateKey, err := signschemes.ByName(testIdentityScheme).GenerateKey()
	require.NoError(t, err)
	keys := newTestEpochKeys(t, t.TempDir(), newEpochClock(CurrentEpoch()))
	l, err := ListenWithEpochKeys("127.0.0.1:0", identityPrivateKey, keys, nil)
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
	defer server.Close()
	var b [1]byte
	_, err = io.ReadFull(server, b[:])
	require.NoError(t, err)

	require.NoError(t, l.Close())
	again, err := ListenWithEpochKeys(addr, identityPrivateKey, keys, nil)
	require.NoError(t, err, "listening again on the port of a closed listener failed")
	again.Close()
	require.NoError(t, server.SetReadDeadline(time.Now().Add(5*time.Second)))
	_, err = server.Read(b[:])
	require.Error(t, err, "closing the listener left an accepted connection open")
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
