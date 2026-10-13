//go:build !linux

package main

import (
	"context"
	"errors"
)

var errNoSessionBus = errors.New("dbus name ownership is unsupported on this platform")

func ownBusName(context.Context, string) (func() error, error) {
	return nil, errNoSessionBus
}
