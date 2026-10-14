// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"bytes"
	"context"
	"crypto/sha256"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/log"
)

func TestPinMismatchIsLoggedOncePerPeerAndEpoch(t *testing.T) {
	impostor, err := quic.ListenAddr("127.0.0.1:0", GenerateTLSConfig(), Config())
	require.NoError(t, err)
	t.Cleanup(func() { impostor.Close() })
	u, err := url.Parse("quic://" + impostor.Addr().String())
	require.NoError(t, err)
	logFile := filepath.Join(t.TempDir(), "dial.log")
	backend, err := log.New(logFile, "WARNING", false)
	require.NoError(t, err)
	defer backend.Close()
	var peer [sha256.Size]byte
	var mismatches QUICPinMismatches
	opts := &Options{PinMismatch: PinMismatchStrict}
	for range 3 {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err := opts.PeerDialer(&mismatches, peer, bytes.Repeat([]byte{2}, sha256.Size), backend.GetLogger("dial"), "peer").Dial(ctx, u, nil)
		cancel()
		require.ErrorIs(t, err, ErrQUICKeyMismatch)
	}
	logged, err := os.ReadFile(logFile)
	require.NoError(t, err)
	require.Equal(t, 1, strings.Count(string(logged), "does not match its published hash"), "a pin mismatch was logged again for the same peer and epoch")
}
