// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	signSchemes "github.com/katzenpost/hpqc/sign/schemes"
	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/core/log"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/quic/common"
)

func TestConnectLogsItsTransport(t *testing.T) {
	_, identityPrivateKey, err := signSchemes.ByName("Ed25519 Sphincs+").GenerateKey()
	require.NoError(t, err)
	keys, err := common.NewEpochKeys(t.TempDir(), common.CurrentEpoch)
	require.NoError(t, err)
	l, err := common.ListenWithEpochKeys("127.0.0.1:0", identityPrivateKey, keys)
	require.NoError(t, err)
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	logFile := filepath.Join(t.TempDir(), "client.log")
	backend, err := log.New(logFile, "DEBUG", false)
	require.NoError(t, err)
	defer backend.Close()

	conn, _ := newGatewayTestConnection(t, &config.UpstreamProxy{})
	conn.log = backend.GetLogger("client/conn")
	conn.descriptor.Addresses = map[string][]string{cpki.TransportQUIC: {"quic://" + l.Addr().String()}}
	startConnect(t, conn)

	var logged string
	require.Eventually(t, func() bool {
		b, err := os.ReadFile(logFile)
		require.NoError(t, err)
		logged = string(b)
		return strings.Contains(logged, "connection established.")
	}, 10*time.Second, 50*time.Millisecond)
	require.Contains(t, logged, "quic connection established.", "the client logged a quic dial as some other transport")
}
