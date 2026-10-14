// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	signschemes "github.com/katzenpost/hpqc/sign/schemes"
	"github.com/stretchr/testify/require"
)

type epochClock struct{ epoch atomic.Uint64 }

func newEpochClock(epoch uint64) *epochClock {
	c := &epochClock{}
	c.epoch.Store(epoch)
	return c
}

func (c *epochClock) now() uint64 { return c.epoch.Load() }

func newTestEpochKeys(t testing.TB, dir string, clock *epochClock) *EpochKeys {
	t.Helper()
	keys, err := NewEpochKeys(dir, clock.now)
	require.NoError(t, err)
	return keys
}

func listenWithEpochKeys(t testing.TB, keys *EpochKeys) *QuicListener {
	t.Helper()
	_, identityPrivateKey, err := signschemes.ByName(testIdentityScheme).GenerateKey()
	require.NoError(t, err)
	l, err := ListenWithEpochKeys("127.0.0.1:0", identityPrivateKey, keys, nil)
	require.NoError(t, err)
	t.Cleanup(func() { l.Close() })
	return l
}

func dialEpochListener(t *testing.T, l *QuicListener, quicKeyHashes []byte) (net.Conn, error) {
	t.Helper()
	u, err := url.Parse("quic://" + l.Addr().String())
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return DialURL(u, ctx, nil, quicKeyHashes, nil)
}

func presentedKeyHash(conn net.Conn) []byte {
	spki := conn.(*QuicConn).Conn.ConnectionState().TLS.PeerCertificates[0].RawSubjectPublicKeyInfo
	keyHash := sha256.Sum256(spki)
	return keyHash[:]
}

func serveEcho(l *QuicListener) {
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()
}

func echoes(t *testing.T, conn net.Conn, msg string) {
	t.Helper()
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	_, err := conn.Write([]byte(msg))
	require.NoError(t, err)
	got := make([]byte, len(msg))
	_, err = io.ReadFull(conn, got)
	require.NoError(t, err)
	require.Equal(t, msg, string(got))
}

func TestEpochKeysHashWindow(t *testing.T) {
	clock := newEpochClock(1000)
	keys := newTestEpochKeys(t, t.TempDir(), clock)
	hashes, err := keys.Hashes(1001)
	require.NoError(t, err)
	require.Len(t, hashes, 3*sha256.Size)
	current, err := keys.Hashes(1000)
	require.NoError(t, err)
	require.Len(t, current, 3*sha256.Size)
	require.Equal(t, hashes[:2*sha256.Size], current[sha256.Size:], "the windows of epochs 1000 and 1001 must share keys 1000 and 1001")
	seen := map[string]bool{}
	for i := 0; i < len(current); i += sha256.Size {
		seen[string(current[i:i+sha256.Size])] = true
	}
	seen[string(hashes[2*sha256.Size:])] = true
	require.Len(t, seen, 4, "each epoch must have its own key")

	stale, err := keys.Hashes(990)
	require.NoError(t, err)
	require.Empty(t, stale, "keys outside N-1 .. N+2 must not be made")
}

func TestEpochKeysRotateAcrossAnEpochBoundary(t *testing.T) {
	clock := newEpochClock(1000)
	keys := newTestEpochKeys(t, t.TempDir(), clock)
	l := listenWithEpochKeys(t, keys)
	serveEcho(l)
	published, err := keys.Hashes(1000)
	require.NoError(t, err)

	before, err := dialEpochListener(t, l, published)
	require.NoError(t, err)
	defer before.Close()
	echoes(t, before, "before")
	require.Equal(t, published[sha256.Size:2*sha256.Size], presentedKeyHash(before))

	clock.epoch.Store(1001)
	after, err := dialEpochListener(t, l, published)
	require.NoError(t, err, "a dialer still on epoch 1000's document must reach the listener in epoch 1001")
	defer after.Close()
	echoes(t, after, "after")
	require.Equal(t, published[2*sha256.Size:], presentedKeyHash(after))
	require.NotEqual(t, presentedKeyHash(before), presentedKeyHash(after))
	echoes(t, before, "established")

	next, err := keys.Hashes(1002)
	require.NoError(t, err)
	early, err := dialEpochListener(t, l, next)
	require.NoError(t, err, "a dialer already on epoch 1002's document must reach the listener in epoch 1001")
	early.Close()
}

func TestEpochKeysExpiredKeyIsRejected(t *testing.T) {
	clock := newEpochClock(1000)
	keys := newTestEpochKeys(t, t.TempDir(), clock)
	l := listenWithEpochKeys(t, keys)
	serveEcho(l)
	published, err := keys.Hashes(1000)
	require.NoError(t, err)
	clock.epoch.Store(1003)
	_, err = dialEpochListener(t, l, published)
	require.ErrorContains(t, err, "QUIC key does not match", "a listener at epoch 1003 still answered with a key epoch 1000 published")

	stuck := newTestEpochKeys(t, t.TempDir(), newEpochClock(1000))
	stale := listenWithEpochKeys(t, stuck)
	serveEcho(stale)
	_, err = dialEpochListener(t, stale, published)
	require.ErrorContains(t, err, "QUIC key does not match")
	current, err := stuck.Hashes(1003)
	require.NoError(t, err)
	_, err = dialEpochListener(t, stale, current)
	require.ErrorContains(t, err, "QUIC key does not match", "epoch 1000's key was accepted against epoch 1003's hashes")
}

func TestEpochKeysPersistAndExpire(t *testing.T) {
	dir := t.TempDir()
	clock := newEpochClock(1000)
	first, err := newTestEpochKeys(t, dir, clock).Hashes(1001)
	require.NoError(t, err)
	again, err := newTestEpochKeys(t, dir, clock).Hashes(1001)
	require.NoError(t, err)
	require.Equal(t, first, again, "a restarted node must present the keys it published")

	for _, e := range []uint64{1000, 1001, 1002} {
		info, err := os.Stat(filepath.Join(dir, fmt.Sprintf("quic-tls-%d.key", e)))
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0600), info.Mode().Perm())
	}

	clock.epoch.Store(1003)
	keys := newTestEpochKeys(t, dir, clock)
	for _, e := range []uint64{1000, 1001} {
		_, err := os.Stat(filepath.Join(dir, fmt.Sprintf("quic-tls-%d.key", e)))
		require.ErrorIs(t, err, os.ErrNotExist, "epoch %d's key outlived its window", e)
	}
	later, err := keys.Hashes(1003)
	require.NoError(t, err)
	require.Equal(t, first[2*sha256.Size:], later[:sha256.Size], "epoch 1002's key must survive to its last epoch")
}

func TestEpochKeysAreIndependent(t *testing.T) {
	clock := newEpochClock(1000)
	_, identityPrivateKey, err := signschemes.ByName(testIdentityScheme).GenerateKey()
	require.NoError(t, err)
	identitySecret, err := identityPrivateKey.MarshalBinary()
	require.NoError(t, err)
	identitySecret = bytes.Clone(identitySecret)

	a := newTestEpochKeys(t, t.TempDir(), clock)
	l, err := ListenWithEpochKeys("127.0.0.1:0", identityPrivateKey, a, nil)
	require.NoError(t, err)
	defer l.Close()
	hashesA, err := a.Hashes(1000)
	require.NoError(t, err)
	hashesB, err := newTestEpochKeys(t, t.TempDir(), clock).Hashes(1000)
	require.NoError(t, err)
	for i := 0; i < len(hashesA); i += sha256.Size {
		require.False(t, bytes.Contains(hashesB, hashesA[i:i+sha256.Size]), "two nodes share an epoch key")
	}
	after, err := identityPrivateKey.MarshalBinary()
	require.NoError(t, err)
	require.Equal(t, identitySecret, after, "listening changed the identity key")
}

func TestEpochKeyCertificateCoversItsWindow(t *testing.T) {
	clock := newEpochClock(CurrentEpoch())
	keys := newTestEpochKeys(t, t.TempDir(), clock)
	cert, err := keys.GetCertificate(nil)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	require.NoError(t, err)
	now := clock.now()
	require.Equal(t, epochStart(now-1), leaf.NotBefore.UTC())
	require.Equal(t, epochStart(now+2), leaf.NotAfter.UTC())
	require.True(t, leaf.NotBefore.Before(time.Now()) && leaf.NotAfter.After(time.Now()))
	require.GreaterOrEqual(t, leaf.SerialNumber.BitLen(), 64)
}
