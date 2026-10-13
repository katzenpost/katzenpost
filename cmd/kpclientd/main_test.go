package main

import (
	"context"
	"fmt"
	"testing"

	"github.com/godbus/dbus/v5"

	"github.com/katzenpost/katzenpost/client/config"
)

func TestExampleDBusNameIsValidWellKnownName(t *testing.T) {
	if err := config.ValidateDBusName(exampleDBusName); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "kpclientd", ".a.b", "a..b", "a.1b", ":1.5", "a b.c"} {
		if err := config.ValidateDBusName(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}

func TestOwnConfiguredDBusName(t *testing.T) {
	original := connectBus
	t.Cleanup(func() { connectBus = original })
	const fromConfig = "network.katzenpost.fromconfig"
	const fromFlag = "network.katzenpost.fromflag"
	for _, test := range []struct {
		label      string
		cfg        Config
		configName string
		reply      dbus.RequestNameReply
		busErr     error
		wantName   string
		wantOwned  bool
		wantErr    bool
	}{
		{label: "the configured name", configName: fromConfig, reply: dbus.RequestNameReplyPrimaryOwner, wantName: fromConfig, wantOwned: true},
		{label: "the flag beats the config", cfg: Config{DBusName: fromFlag, DBusNameSet: true}, configName: fromConfig, reply: dbus.RequestNameReplyPrimaryOwner, wantName: fromFlag, wantOwned: true},
		{label: "an empty flag disables the configured name", cfg: Config{DBusNameSet: true}, configName: fromConfig},
		{label: "no name at all", reply: dbus.RequestNameReplyPrimaryOwner},
		{label: "no session bus", configName: fromConfig, busErr: fmt.Errorf("%w: dial", errNoSessionBus)},
		{label: "another owner", configName: fromConfig, reply: dbus.RequestNameReplyExists, wantName: fromConfig, wantErr: true},
	} {
		t.Run(test.label, func(t *testing.T) {
			bus := &fakeBus{reply: test.reply}
			connectBus = func() (busOwner, error) {
				if test.busErr != nil {
					return nil, test.busErr
				}
				return bus, nil
			}
			owned, err := ownConfiguredDBusName(context.Background(), test.cfg, &config.Config{DBusName: test.configName})
			if (err != nil) != test.wantErr {
				t.Fatalf("unexpected error: %v", err)
			}
			if (owned != nil) != test.wantOwned {
				t.Fatalf("owned %t", owned != nil)
			}
			if bus.name != test.wantName {
				t.Fatalf("requested %q", bus.name)
			}
		})
	}
}
