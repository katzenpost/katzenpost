// SPDX-License-Identifier: AGPL-3.0-only

package kaetzchen

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/server/config"
)

func TestMOTDPrintableBounds(t *testing.T) {
	g := motdGlue(t)
	for _, text := range []string{"a\x1fb", "a\x7fb", "a\x80b", "caf\xc3\xa9", "\x00", "tab\there"} {
		_, err := BuiltInCtors[MOTDCapability](motdConfig(text), g)
		require.ErrorContains(t, err, "non-printable", "%q", text)
	}
	k, err := BuiltInCtors[MOTDCapability](motdConfig(" ~"), g)
	require.NoError(t, err)
	reply, err := k.OnRequest(1, nil, true)
	require.NoError(t, err)
	require.Equal(t, []byte(" ~"), reply)
}

func TestMOTDWithoutConfigIsRejected(t *testing.T) {
	_, err := BuiltInCtors[MOTDCapability](&config.Kaetzchen{Capability: MOTDCapability, Endpoint: "motd"}, motdGlue(t))
	require.Error(t, err)
}

func TestMOTDBadTextFailsTheWorker(t *testing.T) {
	_, err := New(motdGlue(t, motdConfig("")))
	require.ErrorContains(t, err, "kaetzchen/motd")
}
