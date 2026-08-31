//go:build linux

package main

import (
	"fmt"

	"github.com/godbus/dbus/v5"
)

type busOwner interface {
	RequestName(string, dbus.RequestNameFlags) (dbus.RequestNameReply, error)
	Close() error
}

var sessionBus = func() (busOwner, error) {
	return dbus.ConnectSessionBus()
}

func ownBusName(name string) (func() error, error) {
	conn, err := sessionBus()
	if err != nil {
		return nil, err
	}
	reply, err := conn.RequestName(name, dbus.NameFlagDoNotQueue)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if reply != dbus.RequestNameReplyPrimaryOwner {
		conn.Close()
		return nil, fmt.Errorf("D-Bus name %s is already owned", name)
	}
	return conn.Close, nil
}
