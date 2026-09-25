package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

type fakeBus struct {
	reply  dbus.RequestNameReply
	err    error
	name   string
	closed bool
	done   chan struct{}
}

func (b *fakeBus) RequestName(name string, _ dbus.RequestNameFlags) (dbus.RequestNameReply, error) {
	b.name = name
	return b.reply, b.err
}

func (b *fakeBus) Close() error {
	b.closed = true
	if b.done != nil {
		close(b.done)
	}
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
		name    string
		bus     *fakeBus
		wantErr bool
	}{
		{"request", &fakeBus{err: want}, true},
		{"owned", &fakeBus{reply: dbus.RequestNameReplyExists}, true},
		{"success", &fakeBus{reply: dbus.RequestNameReplyPrimaryOwner}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			connectBus = func() (busOwner, error) { return test.bus, nil }
			bus, err := ownBusName(context.Background(), "test")
			if test.wantErr {
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

func TestSessionBusUnreachableDoesNotAutolaunch(t *testing.T) {
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path="+t.TempDir()+"/absent.sock")
	start := time.Now()
	bus, err := sessionBus()
	if bus != nil || !errors.Is(err, errNoSessionBus) {
		t.Fatalf("got bus=%v err=%v", bus != nil, err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("connect attempt took %v", time.Since(start))
	}
}

func TestOwnBusNameTimeoutClosesTheLateBus(t *testing.T) {
	original := connectBus
	t.Cleanup(func() { connectBus = original })
	release := make(chan struct{})
	late := &fakeBus{reply: dbus.RequestNameReplyPrimaryOwner, done: make(chan struct{})}
	connectBus = func() (busOwner, error) {
		<-release
		return late, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	bus, err := ownBusName(ctx, "network.katzenpost.test")
	if bus != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got bus=%t err=%v", bus != nil, err)
	}
	close(release)
	select {
	case <-late.done:
	case <-time.After(5 * time.Second):
		t.Fatal("the late bus was not closed")
	}
}
