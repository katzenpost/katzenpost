// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/hpqc/bacap"

	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/wire/commands"
)

func replicaPayloadLogger(t *testing.T, module string) (*logging.Logger, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "replica.log")
	backend, err := log.New(path, "DEBUG", false)
	require.NoError(t, err)
	return backend.GetLogger(module), path
}

func replicaPayloadLogText(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	return string(b)
}

func TestProxyRequestManagerDoesNotLogEnvelopeHash(t *testing.T) {
	logger, path := replicaPayloadLogger(t, "replica-payload-proxy")
	p := NewProxyRequestManager(logger, time.Minute)
	defer p.Shutdown()

	var envHash [32]byte
	copy(envHash[:], bytes.Repeat([]byte{0xcd}, 32))
	p.RegisterProxyRequest(envHash, nil, nil, nil, [32]byte{1}, "replica9")
	p.FailRequest(envHash, "test")
	p.HandleReply(&commands.ReplicaMessageReply{EnvelopeHash: &envHash})

	text := replicaPayloadLogText(t, path)
	require.Contains(t, text, "replica9")
	require.NotContains(t, text, hex.EncodeToString(envHash[:8]), "envelope hash written to the log")
}

func TestReplicationDoesNotLogBoxID(t *testing.T) {
	env := setupSemaScopeTestServer(t)
	logger, path := replicaPayloadLogger(t, "replica-payload-replication")
	co := &Connector{
		server: env.server,
		log:    logger,
		conns:  make(map[[constants.NodeIDLength]byte]*outgoingConn),
	}

	var boxID [bacap.BoxIDSize]byte
	copy(boxID[:], bytes.Repeat([]byte{0xef}, bacap.BoxIDSize))
	co.doReplication(&commands.ReplicaWrite{BoxID: &boxID})

	text := replicaPayloadLogText(t, path)
	require.Contains(t, text, "REPLICATION")
	require.NotContains(t, text, hex.EncodeToString(boxID[:8]), "BoxID written to the log")
}
