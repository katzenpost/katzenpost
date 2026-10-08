// SPDX-License-Identifier: AGPL-3.0-only

package cborplugin

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestHostInfoRejects(t *testing.T) {
	for _, tc := range []struct{ name, length, geometry string }{
		{"negative length", "-1", ""},
		{"length overflow", "99999999999999999999", ""},
		{"geometry without its table", "", "UserForwardPayloadLength = 2000\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(PluginPayloadLengthEnv, tc.length)
			t.Setenv(PluginGeometryEnv, tc.geometry)
			if h, err := HostInfo(); err == nil {
				t.Fatalf("HostInfo = %+v, nil; want an error", h)
			}
		})
	}
}

func TestOfferHostSocketPassesGeometryWithoutSocket(t *testing.T) {
	dir := filepath.Join(t.TempDir(), strings.Repeat("d", maxSocketPathLen))
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", dir)
	t.Setenv("TMP", dir)
	c := &Client{cmd: exec.Command("true"), Geometry: testGeometry()}
	if socket, err := c.offerHostSocket(); err != nil || socket != "" {
		t.Fatalf("offerHostSocket = %q, %v; want no socket", socket, err)
	}
	requireNoHostOffer(t, c.cmd.Env)
	want := PluginGeometryEnv + "=" + geometryEnv(t, c.Geometry)
	found := false
	for _, kv := range c.cmd.Env {
		found = found || kv == want
	}
	if !found {
		t.Fatal("geometry not passed when the socket path is too long")
	}
}

func TestOfferHostSocketWithoutGeometry(t *testing.T) {
	c := &Client{cmd: exec.Command("true")}
	socket, err := c.offerHostSocket()
	if err != nil || socket == "" {
		t.Fatalf("offerHostSocket = %q, %v", socket, err)
	}
	t.Cleanup(func() { os.RemoveAll(c.hostDir) })
	for _, kv := range c.cmd.Env {
		if strings.HasPrefix(kv, PluginGeometryEnv+"=") || strings.HasPrefix(kv, PluginPayloadLengthEnv+"=") {
			t.Fatalf("host without a geometry passed %q", kv)
		}
	}
}
