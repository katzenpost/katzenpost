//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/godbus/dbus/v5"
)

var errNoSessionBus = errors.New("no session dbus is reachable")

type busOwner interface {
	RequestName(string, dbus.RequestNameFlags) (dbus.RequestNameReply, error)
	Close() error
}

func sessionBus() (busOwner, error) {
	conn, err := dbus.SessionBusPrivateNoAutoStartup()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errNoSessionBus, err)
	}
	if err := conn.Auth(nil); err != nil {
		conn.Close()
		return nil, err
	}
	if err := conn.Hello(); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

var connectBus = sessionBus

func ownBusName(ctx context.Context, name string) (func() error, error) {
	type result struct {
		conn busOwner
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		conn, err := connectBus()
		if err != nil {
			ch <- result{nil, err}
			return
		}
		reply, err := conn.RequestName(name, dbus.NameFlagDoNotQueue)
		if err != nil {
			conn.Close()
			ch <- result{nil, err}
			return
		}
		if reply != dbus.RequestNameReplyPrimaryOwner {
			conn.Close()
			ch <- result{nil, fmt.Errorf("dbus name %s is already owned", name)}
			return
		}
		ch <- result{conn, nil}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			return nil, r.err
		}
		return r.conn.Close, nil
	case <-ctx.Done():
		go func() {
			if r := <-ch; r.conn != nil {
				r.conn.Close()
			}
		}()
		return nil, fmt.Errorf("owning dbus name %s: %w", name, ctx.Err())
	}
}
