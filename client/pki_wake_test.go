// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func newWakeTestConnection(t *testing.T) *connection {
	conn := newTestConnection(t)
	conn.client.pki = &pki{
		c:             conn.client,
		log:           conn.client.logbackend.GetLogger("pki"),
		failedFetches: make(map[uint64]error),
		forceUpdateCh: make(chan interface{}, 1),
	}
	return conn
}

func pkiWoken(p *pki) bool {
	select {
	case <-p.forceUpdateCh:
		return true
	default:
		return false
	}
}

func TestConnectWakesPKIOnceConnected(t *testing.T) {
	conn := newWakeTestConnection(t)
	require.False(t, conn.isConnected.Load())
	conn.onConnStatusChange(nil)
	require.True(t, conn.isConnected.Load())
	require.True(t, pkiWoken(conn.client.pki))
}

func TestConnectWakesPKIAfterAnEarlierWakeWasTaken(t *testing.T) {
	conn := newWakeTestConnection(t)
	conn.client.pki.setClockSkew(3)
	require.True(t, pkiWoken(conn.client.pki))
	conn.onConnStatusChange(nil)
	require.True(t, pkiWoken(conn.client.pki))
}

func TestDisconnectDoesNotWakePKI(t *testing.T) {
	conn := newWakeTestConnection(t)
	conn.isConnected.Store(true)
	conn.onConnStatusChange(errors.New("gone"))
	require.False(t, pkiWoken(conn.client.pki))
}

func TestConnectWithoutPKIStillConnects(t *testing.T) {
	conn := newTestConnection(t)
	require.Nil(t, conn.client.pki)
	conn.onConnStatusChange(nil)
	require.True(t, conn.isConnected.Load())
}

func TestConnectWithAPendingWakeDoesNotBlock(t *testing.T) {
	conn := newWakeTestConnection(t)
	conn.client.ForceFetchPKI()
	conn.onConnStatusChange(nil)
	require.True(t, conn.isConnected.Load())
	require.True(t, pkiWoken(conn.client.pki))
	require.False(t, pkiWoken(conn.client.pki))
}
