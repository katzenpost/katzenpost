// SPDX-License-Identifier: AGPL-3.0-only

package incoming

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/connlimit"
	"github.com/katzenpost/katzenpost/core/log"
)

func TestGatewayLogsCarryNoClientAddress(t *testing.T) {
	p := filepath.Join(t.TempDir(), "gateway.log")
	logBE, err := log.New(p, "DEBUG", false)
	require.NoError(t, err)
	t.Cleanup(func() { _ = logBE.Close() })

	limiter := connlimit.New(1, 1, 0, 0)
	_, ok := limiter.TryAcquire(tcpAddr("10.0.0.9"), false)
	require.True(t, ok)
	peerSet := connlimit.NewPeerSet()
	peerSet.Rebuild([]string{"tcp://192.0.2.1:30001"})
	l, gl := newCapListener(t, limiter, peerSet)
	l.log = logBE.GetLogger("listener")
	l.glue.(*capGlue).logBE = logBE
	go l.worker()

	expectClosed(t, feedConn(gl, "203.0.113.7"), "client over the cap")

	admitted := feedConn(gl, "192.0.2.1")
	_, _ = admitted.Write(make([]byte, 4096))
	admitted.Close()
	require.Eventually(t, func() bool {
		b, _ := os.ReadFile(p)
		return regexp.MustCompile(`Handshake failed|TCP connection closed before`).Match(b)
	}, 10*time.Second, 20*time.Millisecond)
	gl.Close()
	l.l.Close()

	noDoc, noDocGL := newCapListener(t, connlimit.New(8, 8, 0, 0), connlimit.NewPeerSet())
	noDoc.log = logBE.GetLogger("listener")
	noDoc.glue.(*capGlue).pki = &fakePKI{usable: false}
	go noDoc.worker()
	expectClosed(t, feedConn(noDocGL, "198.51.100.6"), "no usable document")
	noDocGL.Close()
	noDoc.l.Close()

	b, err := os.ReadFile(p)
	require.NoError(t, err)
	logged := string(b)
	require.Contains(t, logged, "Refusing connection")
	require.Contains(t, logged, "New incoming connection")
	for _, ip := range []string{"203.0.113.7", "192.0.2.1", "198.51.100.6"} {
		require.NotContains(t, logged, ip)
	}
}
