// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/kem/schemes"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/log"
)

func TestCancelledSessionIsNotLoggedAsAFailedAttempt(t *testing.T) {
	silent, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer silent.Close()
	go func() {
		for {
			c, err := silent.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	logFile := filepath.Join(t.TempDir(), "client.log")
	logBackend, err := log.New(logFile, "DEBUG", false)
	require.NoError(t, err)
	defer logBackend.Close()
	_, linkPriv, err := schemes.ByName("x25519").GenerateKeyPair()
	require.NoError(t, err)
	p := &connector{
		cfg: &Config{LogBackend: logBackend, DialTimeoutSec: 5, HandshakeTimeoutSec: 5, RetryMaxAttempts: 3, RetryBaseDelay: time.Millisecond, RetryMaxDelay: time.Millisecond},
		log: logBackend.GetLogger("connector"),
	}
	peer := &config.Authority{
		Identifier:    "auth1",
		Addresses:     []string{"tcp://" + silent.Addr().String()},
		WireKEMScheme: "x25519",
	}
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(200*time.Millisecond, cancel)
	_, err = p.initSessionWithRetry(ctx, linkPriv, nil, peer)
	require.Error(t, err)
	logged, err := os.ReadFile(logFile)
	require.NoError(t, err)
	require.NotContains(t, string(logged), "attempt 1 failed", "a session its caller cancelled was logged as a failed attempt")
	require.NotContains(t, string(logged), "retry 1/", "a session its caller cancelled was retried")
}
