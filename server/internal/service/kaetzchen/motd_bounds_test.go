// SPDX-License-Identifier: AGPL-3.0-only

package kaetzchen

import (
	"crypto/rand"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	ecdh "github.com/katzenpost/hpqc/nike/x25519"

	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/server/config"
)

var disallowedMOTDs = map[string]string{
	"ANSI color":         "\x1b[31mred",
	"OSC 52 clipboard":   "\x1b]52;c;aGk=\x07",
	"tab":                "a\tb",
	"carriage return":    "a\rb",
	"NUL":                "a\x00b",
	"DEL":                "a\x7fb",
	"zero-width space":   "zero\xe2\x80\x8bwidth",
	"bidi override":      "bidi\xe2\x80\xaeoverride",
	"non-breaking space": "nb\xc2\xa0sp",
	"latin-1":            "caf\xc3\xa9",
	"unit separator":     "a\x1fb",
}

func TestMOTDPrintableBounds(t *testing.T) {
	g := motdGlue(t)
	for name, text := range disallowedMOTDs {
		_, err := BuiltInCtors[MOTDCapability](motdConfig(text), g)
		require.ErrorContains(t, err, "disallowed byte", name)
	}
	_, err := BuiltInCtors[MOTDCapability](motdConfig("\x1b[31m"), g)
	require.ErrorContains(t, err, "offset 0")
	_, err = BuiltInCtors[MOTDCapability](motdConfig("ok\x07"), g)
	require.ErrorContains(t, err, "offset 2")
	clean := "maintenance tonight\n  see https://example.org/ ~\n"
	k, err := BuiltInCtors[MOTDCapability](motdConfig(clean), g)
	require.NoError(t, err)
	reply, err := k.OnRequest(1, nil, true)
	require.NoError(t, err)
	require.Equal(t, []byte(clean), reply)
}

func TestMOTDLengthBound(t *testing.T) {
	g := motdGlue(t)
	_, err := BuiltInCtors[MOTDCapability](motdConfig(strings.Repeat("m\n", 512)), g)
	require.NoError(t, err)
	g.s.cfg.SphinxGeometry = geo.GeometryFromUserForwardPayloadLength(ecdh.Scheme(rand.Reader), 600, true, 5)
	_, err = BuiltInCtors[MOTDCapability](motdConfig(strings.Repeat("m", 601)), g)
	require.Error(t, err, "motd longer than the network's payload")
	_, err = BuiltInCtors[MOTDCapability](motdConfig(strings.Repeat("m", 600)), g)
	require.NoError(t, err)
}

func TestMOTDWithoutConfigIsRejected(t *testing.T) {
	_, err := BuiltInCtors[MOTDCapability](&config.Kaetzchen{Capability: MOTDCapability, Endpoint: "motd"}, motdGlue(t))
	require.Error(t, err)
}

func TestMOTDBadTextFailsTheWorker(t *testing.T) {
	_, err := New(motdGlue(t, motdConfig("")))
	require.ErrorContains(t, err, "kaetzchen/motd")
}
