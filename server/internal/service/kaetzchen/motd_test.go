// SPDX-License-Identifier: AGPL-3.0-only

package kaetzchen

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/server/config"
)

func motdGlue(t *testing.T, kaetzchen ...*config.Kaetzchen) *mockGlue {
	logBackend, err := log.New("", "DEBUG", false)
	require.NoError(t, err)
	p := &mockProvider{userName: "alice"}
	return &mockGlue{s: &mockServer{
		logBackend: logBackend,
		gateway:    p,
		service:    p,
		cfg: &config.Config{
			Server:      &config.Server{},
			Logging:     &config.Logging{},
			ServiceNode: &config.ServiceNode{Kaetzchen: kaetzchen},
			PKI:         &config.PKI{},
			Debug:       &config.Debug{NumKaetzchenWorkers: 1},
		},
	}}
}

func motdConfig(text interface{}) *config.Kaetzchen {
	return &config.Kaetzchen{Capability: "motd", Endpoint: "motd", Config: map[string]interface{}{"Text": text}}
}

func TestMOTDReturnsConfiguredText(t *testing.T) {
	ctor, ok := BuiltInCtors["motd"]
	require.True(t, ok)
	k, err := ctor(motdConfig("maintenance on 2026-11-01"), motdGlue(t))
	require.NoError(t, err)
	require.Equal(t, "motd", k.Capability())
	require.Equal(t, "motd", k.Parameters()[ParameterEndpoint])
	reply, err := k.OnRequest(1, []byte("ignored"), true)
	require.NoError(t, err)
	require.Equal(t, []byte("maintenance on 2026-11-01"), reply)
	_, err = k.OnRequest(2, nil, false)
	require.ErrorIs(t, err, ErrNoResponse)
}

func TestMOTDRejectsBadText(t *testing.T) {
	ctor, ok := BuiltInCtors["motd"]
	require.True(t, ok)
	g := motdGlue(t)
	for _, text := range []interface{}{nil, "", 7, strings.Repeat("m", 513), "line\nbreak"} {
		_, err := ctor(motdConfig(text), g)
		require.Error(t, err, "%v", text)
	}
	_, err := ctor(motdConfig(strings.Repeat("m", 512)), g)
	require.NoError(t, err)
}

func TestMOTDAdvertisedOnlyWhenConfigured(t *testing.T) {
	echo := &config.Kaetzchen{Capability: EchoCapability, Endpoint: "echo", Config: map[string]interface{}{}}
	w, err := New(motdGlue(t, echo))
	require.NoError(t, err)
	_, ok := w.KaetzchenForPKI()["motd"]
	require.False(t, ok)
	w.Halt()

	w, err = New(motdGlue(t, echo, motdConfig("hello")))
	require.NoError(t, err)
	_, ok = w.KaetzchenForPKI()["motd"]
	require.True(t, ok)
	w.Halt()
}
