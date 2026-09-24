package main

import (
	"context"
	"errors"
	"fmt"
	"io"

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
		return nil, errors.Join(err, conn.Close())
	}
	if err := conn.Hello(); err != nil {
		return nil, errors.Join(err, conn.Close())
	}
	return conn, nil
}

var connectBus = sessionBus

func ownBusName(ctx context.Context, name string) (io.Closer, error) {
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
			ch <- result{nil, errors.Join(err, conn.Close())}
			return
		}
		if reply != dbus.RequestNameReplyPrimaryOwner {
			ch <- result{nil, errors.Join(fmt.Errorf("dbus name %s is already owned", name), conn.Close())}
			return
		}
		ch <- result{conn, nil}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			return nil, r.err
		}
		return r.conn, nil
	case <-ctx.Done():
		go func() {
			if r := <-ch; r.conn != nil {
				r.conn.Close()
			}
		}()
		return nil, fmt.Errorf("owning dbus name %s: %w", name, ctx.Err())
	}
}
