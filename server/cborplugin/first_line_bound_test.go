// SPDX-License-Identifier: AGPL-3.0-only

package cborplugin

import (
	"os"
	"strings"
	"testing"
)

func TestClientRejectsAnOverlongFirstLine(t *testing.T) {
	t.Setenv("GO_WANT_HELPER_PROCESS", "1")
	t.Setenv("GO_HELPER_BEHAVIOR", "long_first_line")
	client := newTestClient(t)
	err := client.Start(os.Args[0], []string{"-test.run=TestHelperProcess"})
	if err == nil || !strings.Contains(err.Error(), "first line of 4096 bytes or more") {
		t.Fatalf("Start = %.200v; want a first line too long error", err)
	}
	if len(err.Error()) > 16<<10 {
		t.Fatalf("Start error is %d bytes; the line was read whole", len(err.Error()))
	}
	if client.cmd.ProcessState == nil {
		t.Fatal("Start returned without reaping the plugin")
	}
}
