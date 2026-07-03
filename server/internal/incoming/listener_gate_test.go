// listener_gate_test.go - Tests for the incoming listener admission gate.
// Copyright (C) 2026  The Katzenpost Authors.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.

package incoming

import (
	"container/list"
	"net"
	"sync"
	"testing"
	"time"

	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/katzenpost/server/internal/glue"
)

// fakePKI satisfies glue.PKI; only HasUsableDocument is exercised by the gate.
type fakePKI struct {
	glue.PKI
	usable bool
}

func (f *fakePKI) HasUsableDocument() bool { return f.usable }

// fakeGlue satisfies glue.Glue; only PKI() is exercised by the gate.
type fakeGlue struct {
	glue.Glue
	pki glue.PKI
}

func (g *fakeGlue) PKI() glue.PKI { return g.pki }

type gateAddr struct{}

func (gateAddr) Network() string { return "test" }
func (gateAddr) String() string  { return "test" }

// permError is a permanent net.Error so worker() returns once the listener is
// closed, rather than spinning.
type permError struct{}

func (permError) Error() string   { return "listener closed" }
func (permError) Timeout() bool   { return false }
func (permError) Temporary() bool { return false }

// gateListener feeds a single connection to worker(), then reports a permanent
// error so the accept loop exits cleanly.
type gateListener struct {
	conns     chan net.Conn
	done      chan struct{}
	closeOnce sync.Once
}

func (l *gateListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, permError{}
	}
}

func (l *gateListener) Close() error {
	l.closeOnce.Do(func() { close(l.done) })
	return nil
}

func (l *gateListener) Addr() net.Addr { return gateAddr{} }

// TestListenerRefusesWithoutUsableDocument verifies the accept-time gate closes
// an incoming connection when the gateway holds no usable PKI document. This is
// the boot case the gate must still reject; the complementary admit case (a
// cached previous-epoch document, the bug this change fixes) is covered by
// pki.TestHasUsableDocument.
func TestListenerRefusesWithoutUsableDocument(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	gl := &gateListener{conns: make(chan net.Conn, 1), done: make(chan struct{})}
	gl.conns <- serverConn

	l := &listener{
		glue:       &fakeGlue{pki: &fakePKI{usable: false}},
		log:        logging.MustGetLogger("incoming_gate_test"),
		l:          gl,
		conns:      list.New(),
		closeAllCh: make(chan interface{}),
	}

	// Set the read deadline before starting the gate. A fast rejection closes
	// the pipe, and SetReadDeadline on a closed net.Pipe end returns an error;
	// setting it first keeps that safety-net deadline from racing the close. The
	// gate is expected to close the connection well before the deadline fires.
	if err := clientConn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}

	go l.worker()
	defer gl.Close()

	if _, err := clientConn.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected the gate to close the connection when no usable document is cached")
	}
}
