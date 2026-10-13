// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetCertificateUsesThePregeneratedKeyWithoutTouchingTheDisk(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "quic")
	clock := newEpochClock(CurrentEpoch())
	keys := newTestEpochKeys(t, dir, clock)
	_, err := keys.Hashes(clock.now() + 1)
	require.NoError(t, err)
	require.NoError(t, os.RemoveAll(dir))
	require.NoError(t, os.WriteFile(dir, nil, 0600))

	clock.epoch.Add(1)
	certificate, err := keys.GetCertificate(nil)
	require.NoError(t, err, "a handshake at the epoch boundary went to the disk for a key the PKI worker had already generated")
	require.NotNil(t, certificate)
}
