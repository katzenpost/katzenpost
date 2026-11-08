// SPDX-License-Identifier: AGPL-3.0-only

//go:build go1.27

package common

import (
	"crypto/mldsa"
	"crypto/sha256"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"

	signschemes "github.com/katzenpost/hpqc/sign/schemes"
	"github.com/stretchr/testify/require"
)

var mldsaOptions = &Options{Signature: SignatureMLDSA65}

func requireMLDSA65Peer(t *testing.T, leaf *x509.Certificate) {
	t.Helper()
	require.Equal(t, x509.MLDSA, leaf.PublicKeyAlgorithm)
	require.Equal(t, x509.MLDSA65, leaf.SignatureAlgorithm)
	key, ok := leaf.PublicKey.(*mldsa.PublicKey)
	require.True(t, ok, "%T", leaf.PublicKey)
	require.Equal(t, mldsa.MLDSA65(), key.Parameters())
}

func TestOptionsValidateMLDSA65(t *testing.T) {
	require.NoError(t, mldsaOptions.Validate())
	require.Error(t, (&Options{Signature: "ML-DSA-44"}).Validate())
	require.Error(t, (&Options{Signature: "ed25519"}).Validate())
}

func TestMLDSA65EpochKeysHandshake(t *testing.T) {
	for _, validation := range []string{AddressValidationAlways, AddressValidationOff} {
		clock := newEpochClock(CurrentEpoch())
		keys, err := NewEpochKeys(t.TempDir(), clock.now, mldsaOptions)
		require.NoError(t, err)
		_, identityPrivateKey, err := signschemes.ByName(testIdentityScheme).GenerateKey()
		require.NoError(t, err)
		l, err := ListenWithEpochKeys("127.0.0.1:0", identityPrivateKey, keys, &Options{Signature: SignatureMLDSA65, AddressValidation: validation})
		require.NoError(t, err)
		t.Cleanup(func() { l.Close() })
		serveEcho(l)

		pinned := currentKeyHash(t, keys)
		conn, err := dialEpochListener(t, l, pinned)
		require.NoError(t, err, validation)
		requireMLDSA65Peer(t, conn.(*QuicConn).Conn.ConnectionState().TLS.PeerCertificates[0])
		require.Equal(t, pinned, presentedKeyHash(conn))
		echoes(t, conn, "ml-dsa-65 "+validation)
		conn.Close()

		ed25519Pin := currentKeyHash(t, newTestEpochKeys(t, t.TempDir(), clock))
		_, err = dialEpochListener(t, l, ed25519Pin)
		require.ErrorIs(t, err, ErrQUICKeyMismatch, validation)
	}
}

func TestMLDSA65EpochKeysSurviveRestartAndNeverReuseAnEd25519Seed(t *testing.T) {
	dir := t.TempDir()
	clock := newEpochClock(1000)
	first, err := NewEpochKeys(dir, clock.now, mldsaOptions)
	require.NoError(t, err)
	hashes, err := first.Hashes(1000)
	require.NoError(t, err)
	require.FileExists(t, filepath.Join(dir, "quic-tls-mldsa65-1000.key"))
	require.NoFileExists(t, filepath.Join(dir, "quic-tls-1000.key"))

	again, err := NewEpochKeys(dir, clock.now, mldsaOptions)
	require.NoError(t, err)
	rehashed, err := again.Hashes(1000)
	require.NoError(t, err)
	require.Equal(t, hashes, rehashed, "a restart changed the ML-DSA-65 keys")

	ed, err := NewEpochKeys(dir, clock.now, nil)
	require.NoError(t, err)
	edHashes, err := ed.Hashes(1000)
	require.NoError(t, err)
	for i := 0; i < len(hashes); i += sha256.Size {
		require.NotContains(t, string(edHashes), string(hashes[i:i+sha256.Size]))
	}
	mldsaSeed, err := os.ReadFile(filepath.Join(dir, "quic-tls-mldsa65-1000.key"))
	require.NoError(t, err)
	edSeed, err := os.ReadFile(filepath.Join(dir, "quic-tls-1000.key"))
	require.NoError(t, err)
	require.NotEqual(t, mldsaSeed, edSeed)

	clock.epoch.Store(1010)
	_, err = again.Hashes(1010)
	require.NoError(t, err)
	require.NoFileExists(t, filepath.Join(dir, "quic-tls-mldsa65-1000.key"), "a stale ML-DSA-65 key was kept")
	require.NoFileExists(t, filepath.Join(dir, "quic-tls-1000.key"), "a stale Ed25519 key was kept")
}

func TestMLDSA65StaticKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "quic-tls.key")
	key, err := LoadStaticKey(path, mldsaOptions)
	require.NoError(t, err)
	reread, err := ReadStaticKey(path, mldsaOptions)
	require.NoError(t, err)
	require.Equal(t, key.Hash(), reread.Hash())
	ed, err := ReadStaticKey(path, nil)
	require.NoError(t, err)
	require.NotEqual(t, key.Hash(), ed.Hash())

	_, identityPrivateKey, err := signschemes.ByName(testIdentityScheme).GenerateKey()
	require.NoError(t, err)
	l, err := ListenWithEpochKeys("127.0.0.1:0", identityPrivateKey, key, mldsaOptions)
	require.NoError(t, err)
	t.Cleanup(func() { l.Close() })
	serveEcho(l)
	conn, err := dialEpochListener(t, l, key.Hash())
	require.NoError(t, err)
	defer conn.Close()
	leaf := conn.(*QuicConn).Conn.ConnectionState().TLS.PeerCertificates[0]
	requireMLDSA65Peer(t, leaf)
	epoch := CurrentEpoch()
	require.Equal(t, epochStart(epoch-1), leaf.NotBefore.UTC())
	require.Equal(t, epochStart(epoch+2), leaf.NotAfter.UTC())
	echoes(t, conn, "static ml-dsa-65")
}
