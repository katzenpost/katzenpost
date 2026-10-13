// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/kem/schemes"
	signschemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/quic/common"
)

func TestInitSessionLogsItsTransport(t *testing.T) {
	_, identityPrivateKey, err := signschemes.ByName(testSchemeName).GenerateKey()
	require.NoError(t, err)
	keys, err := common.NewEpochKeys(t.TempDir(), common.CurrentEpoch)
	require.NoError(t, err)
	l, err := common.ListenWithEpochKeys("127.0.0.1:0", identityPrivateKey, keys, nil)
	require.NoError(t, err)
	defer l.Close()
	logFile := filepath.Join(t.TempDir(), "client.log")
	logBackend, err := log.New(logFile, "DEBUG", false)
	require.NoError(t, err)
	defer logBackend.Close()
	_, linkPriv, err := schemes.ByName("x25519").GenerateKeyPair()
	require.NoError(t, err)
	p := &connector{
		cfg: &Config{LogBackend: logBackend, HandshakeTimeoutSec: 1},
		log: logBackend.GetLogger("connector"),
	}
	peer := &config.Authority{
		Identifier:    "auth1",
		Addresses:     []string{"quic://" + l.Addr().String()},
		WireKEMScheme: "x25519",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _ = p.initSession(ctx, linkPriv, nil, peer)
	logged, err := os.ReadFile(logFile)
	require.NoError(t, err)
	require.Contains(t, string(logged), "peer auth1 (quic://"+l.Addr().String()+"): quic connection established.")
}
