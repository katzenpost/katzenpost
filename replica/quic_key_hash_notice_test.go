// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/pki"
)

func TestReplicaLogsAWithheldQUICKeyHash(t *testing.T) {
	setReplicaEpochClock(t, 1000, time.Second)
	client := &servingReplicaPKIClient{}
	fixture, cleanup := createPublishDescriptorTestWorker(t, client)
	defer cleanup()
	server := fixture.server
	logFile := filepath.Join(t.TempDir(), "replica.log")
	server.cfg.Logging.File = logFile
	server.cfg.Logging.Level = "NOTICE"
	require.NoError(t, server.initLogging())
	t.Cleanup(func() { server.logBackend.Close() })
	w, err := newPKIWorkerWithClient(server, client, server.logBackend.GetLogger("replica pkiWorker"))
	require.NoError(t, err)
	server.cfg.PublishQUICKeyHashes = true
	w.descAddrMap[pki.TransportQUIC] = []string{"quic://127.0.0.1:7483"}
	require.NoError(t, w.publishDescriptorIfNeeded(context.Background()))
	logged, err := os.ReadFile(logFile)
	require.NoError(t, err)
	require.Contains(t, string(logged), "Withholding QUICKeyHash for epoch 1001", "a replica withheld its QUIC key hash without a notice in its log")
}
