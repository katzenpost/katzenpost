// SPDX-License-Identifier: AGPL-3.0-only

package cborplugin

import "testing"

func TestHostSocketPath(t *testing.T) {
	cases := []struct {
		name, protocol, socket, want string
		fromHost                     bool
	}{
		{"host offers a socket", "2", "/run/host.socket", "/run/host.socket", true},
		{"old host", "", "", "/tmp/own.socket", false},
		{"socket without protocol", "", "/run/host.socket", "/tmp/own.socket", false},
		{"protocol without socket", "2", "", "/tmp/own.socket", false},
		{"older protocol", "1", "/run/host.socket", "/tmp/own.socket", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(PluginProtocolEnv, tc.protocol)
			t.Setenv(PluginSocketEnv, tc.socket)
			got, fromHost := HostSocketPath("/tmp/own.socket")
			if got != tc.want || fromHost != tc.fromHost {
				t.Fatalf("HostSocketPath = %q, %v; want %q, %v", got, fromHost, tc.want, tc.fromHost)
			}
		})
	}
}
