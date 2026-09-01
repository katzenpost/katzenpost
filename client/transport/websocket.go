// SPDX-FileCopyrightText: Copyright (C) 2026 Bernd Fix
// SPDX-License-Identifier: AGPL-3.0-only

package transport

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"sync"

	"github.com/coder/websocket"
)

// WebsocketListener implements the net.Listener interface for websockets.
type WebsocketListener struct {
	addr        net.Addr      // address of websocket
	connections chan net.Conn // incoming connections
	done        chan struct{} // channel "done" signal
	ln          net.Listener  // bound TCP listener owned by this listener
	server      *http.Server  // webserver serving the websocket handshake
	closeOnce   sync.Once
	closeErr    error
}

// Accept incoming websocket connection.
func (l *WebsocketListener) Accept() (net.Conn, error) {
	select {
	case <-l.done:
		return nil, net.ErrClosed
	default:
	}
	select {
	case conn := <-l.connections:
		return conn, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

// Close websocket listener. Safe to call more than once.
func (l *WebsocketListener) Close() error {
	l.closeOnce.Do(func() {
		close(l.done)
		// free the bound port synchronously, then stop the webserver
		if l.ln != nil {
			l.closeErr = l.ln.Close()
		}
		if l.server != nil {
			l.server.Close()
		}
		for {
			select {
			case conn := <-l.connections:
				conn.Close()
			default:
				return
			}
		}
	})
	return l.closeErr
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
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		host = u.Host
		if u.Scheme == "wss" {
			port = "443"
		} else {
			port = "80"
		}
	}
	// default a missing host to loopback rather than the 0.0.0.0 wildcard
	if host == "" {
		host = "localhost"
	}
	addr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, err
	}

	// instantiate listener
	listener := &WebsocketListener{
		addr:        addr,
		connections: make(chan net.Conn, 100),
		done:        make(chan struct{}),
	}

	// start a webserver to handle websocket connections
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		netConn := websocket.NetConn(context.Background(), conn, websocket.MessageBinary)

		select {
		case listener.connections <- netConn:
		case <-listener.done:
			netConn.Close()
		}
	})
	// bind synchronously so a bind failure is returned to the caller
	ln, err := net.Listen("tcp", addr.String())
	if err != nil {
		return nil, err
	}
	listener.addr = ln.Addr()
	listener.ln = ln
	listener.server = &http.Server{Handler: mux}
	// run webserver in go-routine
	go listener.server.Serve(ln)

	// return listener instance
	return listener, nil
}
