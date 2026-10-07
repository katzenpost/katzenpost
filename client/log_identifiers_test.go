// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/log/logtest"
)

func TestLogCallsCarryNoPerUserIdentifiers(t *testing.T) {
	files := []string{"daemon.go", "connection.go", "incoming_conn.go"}
	found := logtest.ArgsMatching(t, regexp.MustCompile(`(?i)appid|surbid|envelopehash|gcreply\.id|gatewaylabel|^c\.descriptor$|remoteaddr`), files...)
	for _, c := range logtest.Calls(t, files...) {
		if strings.Contains(c.Format, "Received Request from peer application") && !strings.HasPrefix(c.Method, "Debug") {
			found = append(found, c.Pos.String()+": per-request line at "+c.Method)
		}
	}
	require.Empty(t, found)
}
