// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package plugin

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/pigeonservice/common"
	"github.com/katzenpost/katzenpost/server/cborplugin"
)

type upper struct{}

func (upper) Handle(p []byte) []byte { return append([]byte("re:"), p...) }

func newTestPlugin(t *testing.T) (*plugin, chan cborplugin.Command) {
	t.Helper()
	logBackend, err := log.New("", "debug", false)
	require.NoError(t, err)
	pub, priv, err := common.LoadOrGenerateKeypair(t.TempDir(), "test", common.DefaultNIKE)
	require.NoError(t, err)
	out := make(chan cborplugin.Command, 4)
	p := &plugin{
		cfg:   Config{Name: "test", Busy: []byte("busy")},
		log:   logBackend.GetLogger("test"),
		key:   &common.PluginKey{Scheme: common.DefaultNIKE, Public: pub, Private: priv},
		sem:   make(chan struct{}, 2),
		write: func(c cborplugin.Command) { out <- c },
	}
	return p, out
}

func next(t *testing.T, out chan cborplugin.Command) *cborplugin.Response {
	t.Helper()
	select {
	case c := <-out:
		r, ok := c.(*cborplugin.Response)
		require.True(t, ok)
		return r
	case <-time.After(5 * time.Second):
		t.Fatal("no response")
		return nil
	}
}

func TestParametersCarryThePublicKey(t *testing.T) {
	p, out := newTestPlugin(t)
	require.NoError(t, p.OnCommand(cborplugin.NewParametersRequest()))
	r := next(t, out)
	require.True(t, r.IsParametersResponse)

	node := &common.ServiceNode{Params: r.Params}
	pub, err := common.PluginPublicKey(node, common.DefaultNIKE)
	require.NoError(t, err)
	require.Equal(t, p.key.Public.Bytes(), pub.Bytes())
}

func TestRepliesEchoTheSURB(t *testing.T) {
	p, out := newTestPlugin(t)
	surb := []byte("surb")
	at := time.Now()

	require.NoError(t, p.OnCommand(&cborplugin.Request{ID: 1, SURB: surb, Payload: []byte("x"), RequestAt: at, Delay: time.Second}))
	r := next(t, out)
	require.Equal(t, []byte("busy"), r.Payload, "before the handler is ready")
	require.Equal(t, surb, r.SURB)
	require.Equal(t, uint64(1), r.ID)

	p.h = upper{}
	require.NoError(t, p.OnCommand(&cborplugin.Request{ID: 2, SURB: surb, Payload: []byte("x"), RequestAt: at, Delay: time.Second}))
	r = next(t, out)
	require.Equal(t, []byte("re:x"), r.Payload)
	require.Equal(t, surb, r.SURB)
	require.Equal(t, time.Second, r.Delay)
}

func TestKeypairPersists(t *testing.T) {
	dir := t.TempDir()
	pub1, _, err := common.LoadOrGenerateKeypair(dir, "k", common.DefaultNIKE)
	require.NoError(t, err)
	pub2, _, err := common.LoadOrGenerateKeypair(dir, "k", common.DefaultNIKE)
	require.NoError(t, err)
	require.Equal(t, pub1.Bytes(), pub2.Bytes())
}
