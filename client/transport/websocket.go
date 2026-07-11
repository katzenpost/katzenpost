// SPDX-FileCopyrightText: Copyright (C) 2026 Bernd Fix
// SPDX-License-Identifier: AGPL-3.0-only

package transport

import (
	"context"
	"net"
	"net/http"
	"net/url"

	"github.com/coder/websocket"
)

// WebsocketListener implements the net.Listener interface for websockets.
type WebsocketListener struct {
	connections chan net.Conn // incoming connections
	done        chan struct{} // channel "done" signal
	addr        net.Addr      // address of websocket
}

// Accept incoming websocket connection.
func (l *WebsocketListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.connections:
		return conn, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

// Close websocket listener.
func (l *WebsocketListener) Close() error {
	close(l.done)
	return nil
}

// Addr returns the address of the websocket.
func (l *WebsocketListener) Addr() net.Addr {
	return l.addr
}

//----------------------------------------------------------------------

// WsListenConfig configures a websocket listener.
type WsListenConfig struct {
	// Address is the URL of the websocket like "ws://localhost:12345"
	Address string `toml:"Address"`
}

// Listen creates a websocket listener bound to c.Address.
func (c *WsListenConfig) Listen() (net.Listener, error) {

	// convert websocket URL to net.Addr
	u, err := url.Parse(c.Address)
	if err != nil {
		return nil, err
	}
	host := u.Host
	if _, _, err = net.SplitHostPort(host); err != nil {
		if u.Scheme == "wss" {
			host += ":443"
		} else {
			host += ":80"
		}
	}
	addr, err := net.ResolveTCPAddr("tcp", host)
	if err != nil {
		return nil, err
	}

	// instantiate listener
	listener := &WebsocketListener{
		connections: make(chan net.Conn, 100),
		done:        make(chan struct{}),
		addr:        addr,
	}

	// start a webserver to handle websocket connections
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			InsecureSkipVerify: true,
		})
		if err != nil {
			return
		}
		netConn := websocket.NetConn(context.Background(), conn, websocket.MessageText)

		select {
		case listener.connections <- netConn:
		case <-listener.done:
			netConn.Close()
		}
	})
	// run webserver in go-routine
	go func() {
		server := &http.Server{Addr: addr.String(), Handler: mux}
		go func() {
			<-listener.done
			server.Shutdown(context.Background())
		}()
		server.ListenAndServe()
	}()

	// return listener instance
	return listener, nil
}
