// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package client

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/client/thin"
	"github.com/katzenpost/katzenpost/core/log"
)

func TestEncryptWriteDoesNotLogBlindingFactor(t *testing.T) {
	d, appID, responseCh := setupDaemonWithMockConn(t)
	path := filepath.Join(t.TempDir(), "daemon.log")
	backend, err := log.New(path, "debug", false)
	require.NoError(t, err)
	d.log = backend.GetLogger("encrypt-write-log-secret")

	writeCap, err := bacap.NewWriteCap(rand.Reader)
	require.NoError(t, err)
	idx := writeCap.GetMessageBoxIndex()

	d.encryptWrite(&Request{AppID: appID, EncryptWrite: &thin.EncryptWrite{
		QueryID: &[thin.QueryIDLength]byte{1}, Plaintext: []byte("hello"), WriteCap: writeCap, MessageBoxIndex: idx,
	}})
	select {
	case resp := <-responseCh:
		require.Equal(t, thin.ThinClientSuccess, resp.EncryptWriteReply.ErrorCode)
	case <-time.After(5 * time.Second):
		t.Fatal("no response")
	}

	b, err := os.ReadFile(path)
	require.NoError(t, err)
	text := string(b)
	require.Contains(t, text, "encryptWrite")
	require.NotContains(t, text, hex.EncodeToString(idx.CurBlindingFactor[:8]), "blinding factor written to the log")
}
