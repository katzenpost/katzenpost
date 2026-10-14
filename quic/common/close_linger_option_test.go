// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/BurntSushi/toml"
	signschemes "github.com/katzenpost/hpqc/sign/schemes"
	"github.com/stretchr/testify/require"
)

func TestCloseLingerOptionValidates(t *testing.T) {
	for _, line := range []string{"", `CloseLinger = "0s"`, `CloseLinger = "500ms"`, `CloseLinger = "5m"`} {
		var o Options
		require.NoError(t, toml.Unmarshal([]byte(line), &o))
		require.NoError(t, o.Validate(), line)
	}
	for _, value := range []string{"-1ns", "-30s"} {
		var o Options
		require.NoError(t, toml.Unmarshal([]byte(fmt.Sprintf("CloseLinger = %q", value)), &o))
		require.Error(t, o.Validate(), "CloseLinger = %q", value)
	}
}

func TestCloseLingerDefaultsToThirtySeconds(t *testing.T) {
	require.Equal(t, 30*time.Second, closeLinger)
}

func closedEndGoesAway(t *testing.T, closer net.Conn, bound time.Duration) {
	t.Helper()
	require.NoError(t, closer.Close())
	select {
	case <-closer.(*QuicConn).Conn.Context().Done():
	case <-time.After(bound):
		t.Fatalf("Close lingered past %v behind a silent peer", bound)
	}
}

func lingerPair(t *testing.T, opts *Options) (net.Conn, net.Conn) {
	t.Helper()
	_, identityPrivateKey, err := signschemes.ByName(testIdentityScheme).GenerateKey()
	require.NoError(t, err)
	key, err := LoadStaticKey(filepath.Join(t.TempDir(), "quic-tls.key"))
	require.NoError(t, err)
	l, err := ListenWithEpochKeys("127.0.0.1:0", identityPrivateKey, key, opts)
	require.NoError(t, err)
	t.Cleanup(func() { l.Close() })
	u, err := url.Parse("quic://" + l.Addr().String())
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := DialURL(u, ctx, nil, key.Hash(), opts)
	require.NoError(t, err)
	t.Cleanup(func() { client.Close() })
	_, err = client.Write([]byte{0})
	require.NoError(t, err)
	server, err := l.Accept()
	require.NoError(t, err)
	t.Cleanup(func() { server.Close() })
	var b [1]byte
	_, err = server.Read(b[:])
	require.NoError(t, err)
	return client, server
}

func TestCloseLingerOptionBoundsTheListenerSide(t *testing.T) {
	var opts Options
	require.NoError(t, toml.Unmarshal([]byte(`CloseLinger = "500ms"`), &opts))
	_, server := lingerPair(t, &opts)
	closedEndGoesAway(t, server, 1500*time.Millisecond)
}

func TestCloseLingerOptionBoundsTheDialerSide(t *testing.T) {
	var opts Options
	require.NoError(t, toml.Unmarshal([]byte(`CloseLinger = "500ms"`), &opts))
	client, _ := lingerPair(t, &opts)
	closedEndGoesAway(t, client, 1500*time.Millisecond)
}
