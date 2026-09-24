//go:build !linux

package main

import (
	"context"
	"errors"
	"io"
)

var errNoSessionBus = errors.New("dbus name ownership is unsupported on this platform")

func ownBusName(context.Context, string) (io.Closer, error) {
	return nil, errNoSessionBus
}
