// SPDX-FileCopyrightText: Copyright (C) 2026 Bernd Fix
// SPDX-License-Identifier: AGPL-3.0-only

package transport

import (
	"context"
	"net"

	"github.com/coder/websocket"
)

// WsDialConfig configures a websocket dialer.
type WsDialConfig struct {
	// Address is the path to the websocket.
	Address string `toml:"Address"`
}

// Dial opens a websocket connection to c.Address.
func (c *WsDialConfig) Dial() (net.Conn, error) {
	ctx := context.Background()
	conn, _, err := websocket.Dial(ctx, c.Address, nil)
	if err != nil {
		return nil, err
	}
	netConn := websocket.NetConn(ctx, conn, websocket.MessageBinary)
	return netConn, nil
}
