// SPDX-License-Identifier: AGPL-3.0-only

package mixkeys

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/nike/x25519"

	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/server/internal/mixkey"
)

func TestGenerateReplacesKeyWithoutReplayState(t *testing.T) {
	dir := t.TempDir()
	g := geo.GeometryFromUserForwardPayloadLength(x25519.Scheme(rand.Reader), 2000, true, 5)
	k, err := mixkey.New(0, g)
	require.NoError(t, err)
	old := k.PublicBytes()
	priv := k.PrivateKey().(interface{ Bytes() []byte }).Bytes()
	k.Deref()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "mixkey-0.bin"), append([]byte("KMK1\x00"), priv...), 0600))

	logBackend, err := log.New("", "DEBUG", false)
	require.NoError(t, err)
	m := &mixKeys{
		geo:               g,
		persistOnShutdown: true,
		keyStoreDir:       dir,
		log:               logBackend.GetLogger("mixkeys_test"),
		keys:              make(map[uint64]*mixkey.MixKey),
	}
	_, err = m.Generate(0)
	require.NoError(t, err)
	got, ok := m.Get(0)
	require.True(t, ok)
	require.NotEqual(t, old, got, "a key whose replay state was lost is not reused")
	for _, k := range m.keys {
		k.Deref()
	}
}
