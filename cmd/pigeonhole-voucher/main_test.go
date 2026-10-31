// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/log"
	ps "github.com/katzenpost/katzenpost/pigeonservice"
	"github.com/katzenpost/katzenpost/pigeonservice/directory"
	"github.com/katzenpost/katzenpost/pigeonservice/phtest"
	"github.com/katzenpost/katzenpost/pigeonservice/router"
)

const poll = 10 * time.Millisecond

func pluginKey(t *testing.T) *ps.PluginKey {
	pub, priv, err := ps.DefaultNIKE.GenerateKeyPair()
	require.NoError(t, err)
	return &ps.PluginKey{Scheme: ps.DefaultNIKE, Public: pub, Private: priv}
}

// TestSend lists an echo service, then sends it a voucher minted as a chat app mints one, and
// talks to it over the session the service inducts.
func TestSend(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	logBackend, err := log.New("", "debug", false)
	require.NoError(t, err)
	net := phtest.NewNetwork()

	rk := pluginKey(t)
	r, err := router.New(router.Config{
		Key: rk, DBPath: filepath.Join(t.TempDir(), "router.db"),
		PollInterval: poll, Retention: time.Hour, Log: logBackend.GetLogger("router"),
	}, net)
	require.NoError(t, err)
	t.Cleanup(func() { r.Close() })
	net.AddService(ps.RouterCapability, [32]byte{0xa0}, ps.RouterCapability, ps.PluginParams(rk),
		func(_ context.Context, p []byte) []byte { return r.Handle(p) })
	dk := pluginKey(t)
	d, err := directory.New(directory.Config{
		Key: dk, DBPath: filepath.Join(t.TempDir(), "directory.db"),
		RefreshInterval: time.Hour, Log: logBackend.GetLogger("directory"),
	}, net)
	require.NoError(t, err)
	t.Cleanup(func() { d.Close() })
	net.AddService(ps.DirectoryCapability, [32]byte{0xdd}, ps.DirectoryCapability, ps.PluginParams(dk),
		func(_ context.Context, p []byte) []byte { return d.Handle(p) })

	dataDir := t.TempDir()
	key, err := ps.LoadServiceKey(dataDir)
	require.NoError(t, err)
	adv, err := directory.NewClient(net, key, poll)
	require.NoError(t, err)
	svc, err := ps.NewService(ps.Config{
		Key: key, DataDir: dataDir, DisplayName: "echo", Advertiser: adv,
		PollInterval: poll, Retention: time.Hour, Log: logBackend.GetLogger("service"),
	}, net)
	require.NoError(t, err)
	go svc.Run(ctx, ps.HandlerFunc(func(ctx context.Context, s *ps.Session) {
		for {
			msg, err := s.Recv(ctx)
			if err != nil || s.Send(ctx, append([]byte("echo: "), msg...)) != nil {
				return
			}
		}
	}))
	t.Cleanup(func() { cancel(); svc.Close() })

	dir, err := directory.NewAll(net, nil, poll)
	require.NoError(t, err)
	id := svc.ID()
	want := hex.EncodeToString(id[:]) + " 1 routers\n"
	require.Eventually(t, func() bool {
		var out bytes.Buffer
		return list(ctx, dir, &out) == nil && out.String() == want
	}, 20*time.Second, 50*time.Millisecond)

	app, err := ps.Mint(ctx, net, "bob")
	require.NoError(t, err)
	require.NoError(t, send(ctx, net, dir, hex.EncodeToString(id[:]), base64.StdEncoding.EncodeToString(app.Voucher)+"\n"))
	conn, err := app.Await(ctx, net, poll)
	require.NoError(t, err)
	require.NoError(t, conn.Send(ctx, []byte("hello")))
	got, err := conn.Recv(ctx)
	require.NoError(t, err)
	require.Equal(t, "echo: hello", string(got))

	require.ErrorContains(t, send(ctx, net, dir, "abcd", "AAAA"), "service identity is 64 hex digits")
	require.ErrorContains(t, send(ctx, net, dir, hex.EncodeToString(id[:]), "not base64!"), "base64")
}
