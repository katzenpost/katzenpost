// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !wasm

package transport

import (
	"errors"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// Listen creates a unix-domain-socket listener bound to c.Address.
func (c *UnixListenConfig) Listen() (Listener, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	addresses := append([]string{c.Address}, c.Addresses...)
	listeners := make([]Listener, 0, len(addresses))
	for _, address := range addresses {
		addr := &net.UnixAddr{Name: os.ExpandEnv(address), Net: "unix"}
		listener, err := net.ListenUnix("unix", addr)
		if err != nil {
			closeListeners(listeners)
			return nil, err
		}
		listeners = append(listeners, listener)
	}
	if len(listeners) == 1 {
		return listeners[0], nil
	}
	return newMultiListener(listeners, c.log), nil
}

type multiListener struct {
	listeners []Listener
	log       Logger
	accepted  chan net.Conn
	done      chan struct{}
	drained   chan struct{}
	closeOnce sync.Once
	wg        sync.WaitGroup
}

func newMultiListener(listeners []Listener, log Logger) *multiListener {
	m := &multiListener{
		listeners: listeners,
		log:       log,
		accepted:  make(chan net.Conn),
		done:      make(chan struct{}),
		drained:   make(chan struct{}),
	}
	m.wg.Add(len(listeners))
	for _, listener := range listeners {
		go m.accept(listener)
	}
	go func() {
		m.wg.Wait()
		close(m.drained)
	}()
	return m
}

const acceptRetryDelay = 5 * time.Millisecond

func (m *multiListener) accept(listener Listener) {
	defer m.wg.Done()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				select {
				case <-time.After(acceptRetryDelay):
					continue
				case <-m.done:
					return
				}
			}
			if m.log != nil && !isClosing(m.done) {
				m.log.Errorf("unix listener %s retired: %v", listener.Addr(), err)
			}
			listener.Close()
			return
		}
		select {
		case m.accepted <- conn:
		case <-m.done:
			conn.Close()
			return
		}
	}
}

func (m *multiListener) Accept() (net.Conn, error) {
	select {
	case conn := <-m.accepted:
		return conn, nil
	case <-m.done:
		return nil, net.ErrClosed
	case <-m.drained:
		return nil, net.ErrClosed
	}
}

func (m *multiListener) Close() error {
	err := net.ErrClosed
	m.closeOnce.Do(func() {
		close(m.done)
		err = closeListeners(m.listeners)
	})
	m.wg.Wait()
	return err
}

func (m *multiListener) Addr() net.Addr {
	addrs := make(multiAddr, len(m.listeners))
	for i, l := range m.listeners {
		addrs[i] = l.Addr()
	}
	return addrs
}

type multiAddr []net.Addr

func (m multiAddr) Network() string { return m[0].Network() }

func (m multiAddr) String() string {
	s := make([]string, len(m))
	for i, a := range m {
		s[i] = a.String()
	}
	return strings.Join(s, ", ")
}

func isClosing(done chan struct{}) bool {
	select {
	case <-done:
		return true
	default:
		return false
	}
}

func closeListeners(listeners []Listener) error {
	errs := make([]error, 0, len(listeners))
	for _, listener := range listeners {
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
