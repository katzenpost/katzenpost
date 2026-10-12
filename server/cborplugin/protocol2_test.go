// SPDX-License-Identifier: AGPL-3.0-only

package cborplugin

import (
	"os"
	"testing"
)

func TestClientSpeaksProtocol2(t *testing.T) {
	for _, tc := range []struct {
		behavior string
		want     bool
	}{
		{"host_socket", true},
		{"noisy_stdout", false},
	} {
		t.Run(tc.behavior, func(t *testing.T) {
			t.Setenv("GO_WANT_HELPER_PROCESS", "1")
			t.Setenv("GO_HELPER_BEHAVIOR", tc.behavior)
			client := newEchoClient(t)
			if err := client.Start(os.Args[0], []string{"-test.run=TestHelperProcess"}); err != nil {
				t.Fatalf("Start: %v", err)
			}
			t.Cleanup(func() { client.cmd.Process.Kill() })
			if got := client.SpeaksProtocol2(); got != tc.want {
				t.Fatalf("SpeaksProtocol2 = %v, want %v", got, tc.want)
			}
		})
	}
}
