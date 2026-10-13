// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"context"
	"crypto/sha256"
	"net/url"
	"testing"
	"time"

	signschemes "github.com/katzenpost/hpqc/sign/schemes"
	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"
)

func dialPinned(t *testing.T, addr string, quicKeyHashes []byte) error {
	t.Helper()
	u, err := url.Parse("quic://" + addr)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := DialURL(u, ctx, nil, quicKeyHashes)
	if err == nil {
		conn.Close()
	}
	return err
}

func currentKeyHash(t *testing.T, keys *EpochKeys) []byte {
	t.Helper()
	now := keys.now()
	hashes, err := keys.Hashes(now)
	require.NoError(t, err)
	return hashes[sha256.Size : 2*sha256.Size]
}

func TestDialURLPinsTheQUICKey(t *testing.T) {
	scheme := signschemes.ByName(testIdentityScheme)
	_, identityPrivateKey, err := scheme.GenerateKey()
	require.NoError(t, err)
	clock := newEpochClock(CurrentEpoch())
	keys := newTestEpochKeys(t, t.TempDir(), clock)
	l, err := ListenWithEpochKeys("127.0.0.1:0", identityPrivateKey, keys)
	require.NoError(t, err)
	defer l.Close()
	addr := l.Addr().String()
	pinned := currentKeyHash(t, keys)
	other := currentKeyHash(t, newTestEpochKeys(t, t.TempDir(), clock))

	require.NoError(t, dialPinned(t, addr, pinned), "pinned key")
	require.NoError(t, dialPinned(t, addr, nil), "no pin")
	require.NoError(t, dialPinned(t, addr, append(append([]byte{}, other...), pinned...)), "new key second")
	require.NoError(t, dialPinned(t, addr, append(append([]byte{}, pinned...), other...)), "new key first")
	require.ErrorContains(t, dialPinned(t, addr, other), "QUIC key does not match", "wrong key")
	require.ErrorContains(t, dialPinned(t, addr, append(append([]byte{}, other...), other...)), "QUIC key does not match", "two wrong keys")
	require.ErrorContains(t, dialPinned(t, addr, pinned[:16]), "QUIC key does not match", "truncated pin")
	require.ErrorContains(t, dialPinned(t, addr, append(append([]byte{}, pinned...), 0)), "QUIC key does not match", "pin with a trailing byte")
}

func TestPinnedDialRefusesAnUnpinnedListener(t *testing.T) {
	pinned := currentKeyHash(t, newTestEpochKeys(t, t.TempDir(), newEpochClock(CurrentEpoch())))
	ql, err := quic.ListenAddr("127.0.0.1:0", GenerateTLSConfig(), Config())
	require.NoError(t, err)
	defer ql.Close()
	require.ErrorContains(t, dialPinned(t, ql.Addr().String(), pinned), "QUIC key does not match")
}
