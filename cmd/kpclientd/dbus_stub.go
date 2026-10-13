//go:build !linux

package main

import (
	"context"
	"errors"
)

func ownBusName(context.Context, string) (func() error, error) {
	return nil, errors.New("dbus name ownership is unsupported on this platform")
}
