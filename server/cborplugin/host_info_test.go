// SPDX-License-Identifier: AGPL-3.0-only

package cborplugin

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"os"
	"testing"

	"github.com/katzenpost/hpqc/nike/x25519"

	"github.com/katzenpost/katzenpost/core/sphinx/geo"
)

func testGeometry() *geo.Geometry {
	return geo.GeometryFromUserForwardPayloadLength(x25519.Scheme(rand.Reader), 2000, true, 5)
}

func geometryEnv(t *testing.T, g *geo.Geometry) string {
	t.Helper()
	blob, err := g.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return string(blob)
}

func TestHostInfo(t *testing.T) {
	g := testGeometry()
	t.Run("old host", func(t *testing.T) {
		t.Setenv(PluginPayloadLengthEnv, "")
		t.Setenv(PluginGeometryEnv, "")
		h, err := HostInfo()
		if err != nil || h.UserForwardPayloadLength != 0 || h.Geometry != nil {
			t.Fatalf("HostInfo = %+v, %v", h, err)
		}
	})
	t.Run("host passes geometry", func(t *testing.T) {
		t.Setenv(PluginPayloadLengthEnv, "2000")
		t.Setenv(PluginGeometryEnv, geometryEnv(t, g))
		h, err := HostInfo()
		if err != nil {
			t.Fatal(err)
		}
		if h.UserForwardPayloadLength != 2000 || h.Geometry == nil || !bytes.Equal(h.Geometry.Hash(), g.Hash()) {
			t.Fatalf("HostInfo = %+v", h)
		}
	})
	t.Run("bad length", func(t *testing.T) {
		t.Setenv(PluginPayloadLengthEnv, "lots")
		t.Setenv(PluginGeometryEnv, "")
		if _, err := HostInfo(); err == nil {
			t.Fatal("bad length accepted")
		}
	})
	t.Run("bad geometry", func(t *testing.T) {
		t.Setenv(PluginPayloadLengthEnv, "")
		t.Setenv(PluginGeometryEnv, "not toml [")
		if _, err := HostInfo(); err == nil {
			t.Fatal("bad geometry accepted")
		}
	})
}

func runHostGeometryHelper() {
	h, err := HostInfo()
	if err != nil || h.Geometry == nil || h.UserForwardPayloadLength != 2000 || !bytes.Equal(h.Geometry.Hash(), testGeometry().Hash()) {
		fmt.Fprintf(os.Stderr, "host passed no usable geometry: %+v %v\n", h, err)
		os.Exit(3)
	}
	runHostSocketHelper()
}

func TestClientPassesGeometry(t *testing.T) {
	t.Setenv("GO_WANT_HELPER_PROCESS", "1")
	t.Setenv("GO_HELPER_BEHAVIOR", "host_geometry")

	client := newEchoClient(t)
	client.Geometry = testGeometry()
	if err := client.Start(os.Args[0], []string{"-test.run=TestHelperProcess"}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { client.cmd.Process.Kill() })
	requireEcho(t, client)
}
