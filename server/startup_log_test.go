// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/server/config"
)

func TestLogConfigIdentity(t *testing.T) {
	p := filepath.Join(t.TempDir(), "notice.log")
	lb, err := log.New(p, "NOTICE", false)
	require.NoError(t, err)
	cfg := &config.Config{Server: &config.Server{Identifier: "mix0"}}
	s := &Server{cfg: cfg, logBackend: lb, log: lb.GetLogger("mix0")}
	s.logConfigIdentity()
	b, err := os.ReadFile(p)
	require.NoError(t, err)
	h := cfg.Hash()
	require.Contains(t, string(b), "Server identifier is: 'mix0'")
	require.Contains(t, string(b), fmt.Sprintf("Config hash: %x", h[:]))
}
