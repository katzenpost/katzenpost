// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	ecdh "github.com/katzenpost/hpqc/nike/x25519"

	"github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/core/log"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
)

func TestBandwidthLogFollowsTheDecoySetting(t *testing.T) {
	g := geo.GeometryFromUserForwardPayloadLength(ecdh.Scheme(rand.Reader), 2000, true, 5)
	for _, tc := range []struct {
		disable bool
		want    string
	}{
		{false, "Estimated bandwidth: 1.50 packets/s"},
		{true, "Estimated bandwidth: 1.00 packets/s"},
	} {
		logFile := filepath.Join(t.TempDir(), "log")
		backend, err := log.New(logFile, "INFO", false)
		require.NoError(t, err)
		t.Cleanup(func() { backend.Close() })
		d := &Daemon{
			log: backend.GetLogger("bandwidth test"),
			cfg: &config.Config{SphinxGeometry: g, Debug: &config.Debug{DisableDecoyTraffic: tc.disable}},
		}
		d.logBandwidth(&cpki.Document{LambdaP: 0.001, LambdaL: 0.0005}, 0)
		b, err := os.ReadFile(logFile)
		require.NoError(t, err)
		require.Contains(t, string(b), tc.want)
	}
}
