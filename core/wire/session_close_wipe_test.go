// SPDX-License-Identifier: AGPL-3.0-only

package wire

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

type keyedAtCloseConn struct {
	net.Conn
	s     *Session
	keyed bool
}

func (c *keyedAtCloseConn) Close() error {
	c.s.txKeyMutex.Lock()
	c.keyed = c.s.tx.HasKey()
	c.s.txKeyMutex.Unlock()
	return c.Conn.Close()
}

func TestSessionCloseUnkeysCipherStatesAfterConnClose(t *testing.T) {
	alice, bob := deadlineTestConfigs(t)
	sA, sB, cA, cB := establishTestPair(t, alice, bob)
	defer sB.Close()
	defer cB.Close()

	tx, rx := sA.tx, sA.rx
	require.True(t, tx.HasKey())
	require.True(t, rx.HasKey())

	conn := &keyedAtCloseConn{Conn: cA, s: sA}
	sA.conn = conn
	sA.Close()

	require.True(t, conn.keyed, "cipher state was unkeyed while the connection was still open")
	require.False(t, tx.HasKey(), "tx cipher state still keyed after Close")
	require.False(t, rx.HasKey(), "rx cipher state still keyed after Close")
}
