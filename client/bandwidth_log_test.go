// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	ecdh "github.com/katzenpost/hpqc/nike/x25519"

	"github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/core/log"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
)

func TestBandwidthLoggedWhenRatesChange(t *testing.T) {
	logFile := filepath.Join(t.TempDir(), "log")
	backend, err := log.New(logFile, "INFO", false)
	require.NoError(t, err)
	t.Cleanup(func() { backend.Close() })
	g := geo.GeometryFromUserForwardPayloadLength(ecdh.Scheme(rand.Reader), 2000, true, 5)
	d := &Daemon{
		log: backend.GetLogger("bandwidth test"),
		cfg: &config.Config{SphinxGeometry: g, Debug: &config.Debug{}},
	}
	count := func() int {
		b, err := os.ReadFile(logFile)
		require.NoError(t, err)
		return strings.Count(string(b), "Estimated bandwidth")
	}

	d.logBandwidth(&cpki.Document{LambdaP: 0.001, LambdaL: 0.0005}, 1000)
	require.Equal(t, 1, count())
	d.logBandwidth(&cpki.Document{LambdaP: 0.001, LambdaL: 0.0005}, 1200)
	require.Equal(t, 1, count())
	d.logBandwidth(&cpki.Document{LambdaP: 0.002, LambdaL: 0.0005}, 1200)
	require.Equal(t, 2, count())
}
