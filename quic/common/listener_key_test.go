// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"bytes"
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/katzenpost/hpqc/sign"
	signschemes "github.com/katzenpost/hpqc/sign/schemes"
	"github.com/stretchr/testify/require"
)

func presentedSPKI(t *testing.T, identityPrivateKey sign.PrivateKey, keys *EpochKeys) []byte {
	t.Helper()
	l, err := ListenWithEpochKeys("127.0.0.1:0", identityPrivateKey, keys, nil)
	require.NoError(t, err)
	defer l.Close()
	u, err := url.Parse("quic://" + l.Addr().String())
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := DialURL(u, ctx, nil, nil, nil)
	require.NoError(t, err)
	defer conn.Close()
	return conn.(*QuicConn).Conn.ConnectionState().TLS.PeerCertificates[0].RawSubjectPublicKeyInfo
}

func TestListenerKeySurvivesRestart(t *testing.T) {
	for _, schemeName := range []string{"Ed25519", testIdentityScheme} {
		scheme := signschemes.ByName(schemeName)
		_, identityPrivateKey, err := scheme.GenerateKey()
		require.NoError(t, err)
		identitySecret, err := identityPrivateKey.MarshalBinary()
		require.NoError(t, err)
		identitySecret = bytes.Clone(identitySecret)
		clock := newEpochClock(CurrentEpoch())
		dir := t.TempDir()

		first := presentedSPKI(t, identityPrivateKey, newTestEpochKeys(t, dir, clock))
		require.Equal(t, first, presentedSPKI(t, identityPrivateKey, newTestEpochKeys(t, dir, clock)), "%s: a restarted listener presented a new key", schemeName)
		require.NotEqual(t, first, presentedSPKI(t, identityPrivateKey, newTestEpochKeys(t, t.TempDir(), clock)), schemeName)
		after, err := identityPrivateKey.MarshalBinary()
		require.NoError(t, err)
		require.Equal(t, identitySecret, after, "%s: listening changed the identity key", schemeName)
	}
}
