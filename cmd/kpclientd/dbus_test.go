package main

import (
	"context"
	"errors"
	"testing"

	"github.com/godbus/dbus/v5"
)

type fakeBus struct {
	reply  dbus.RequestNameReply
	err    error
	closed bool
}

func (b *fakeBus) RequestName(string, dbus.RequestNameFlags) (dbus.RequestNameReply, error) {
	return b.reply, b.err
}

func (b *fakeBus) Close() error {
	b.closed = true
	return nil
}

func TestOwnBusName(t *testing.T) {
	original := connectBus
	t.Cleanup(func() { connectBus = original })
	want := errors.New("test")
	connectBus = func() (busOwner, error) { return nil, want }
	bus, err := ownBusName(context.Background(), "test")
	if !errors.Is(err, want) || bus != nil {
		t.Fatalf("unexpected result: bus=%t, err=%v", bus != nil, err)
	}
	for _, test := range []struct {
		name string
		bus  *fakeBus
	}{
		{"request", &fakeBus{err: want}},
		{"owned", &fakeBus{reply: dbus.RequestNameReplyExists}},
		{"success", &fakeBus{reply: dbus.RequestNameReplyPrimaryOwner}},
	} {
		t.Run(test.name, func(t *testing.T) {
			connectBus = func() (busOwner, error) { return test.bus, nil }
			bus, err := ownBusName(context.Background(), "test")
			if test.name != "success" {
				if err == nil || !test.bus.closed {
					t.Fatalf("got %v, closed %v", err, test.bus.closed)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			bus.Close()
			if !test.bus.closed {
				t.Fatal("bus not closed")
			}
		})
	}
}
