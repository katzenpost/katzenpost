//go:build fuzz

// SPDX-License-Identifier: AGPL-3.0-only

package commands

import (
	"testing"

	nikeSchemes "github.com/katzenpost/hpqc/nike/schemes"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/core/sphinx"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
)

func fuzzSeeds(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	f.Add(make([]byte, 256))
}

func checkFromBytes(t *testing.T, cmds *Commands, data []byte) {
	cmd, err := cmds.FromBytes(data)
	if err != nil {
		return
	}
	if cmd == nil {
		t.Fatal("FromBytes returned nil command and nil error")
	}
}

func FuzzMixnetCommandsFromBytes(f *testing.F) {
	nike := nikeSchemes.ByName("x25519")
	g := geo.GeometryFromUserForwardPayloadLength(nike, 123, true, 5)
	cmds := NewMixnetCommands(sphinx.NewSphinx(g).Geometry())
	fuzzSeeds(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		checkFromBytes(t, cmds, data)
	})
}

func FuzzPKICommandsFromBytes(f *testing.F) {
	cmds := NewPKICommands(signSchemes.ByName("ed25519"))
	fuzzSeeds(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		checkFromBytes(t, cmds, data)
	})
}

func FuzzStorageReplicaCommandsFromBytes(f *testing.F) {
	nike := nikeSchemes.ByName("x25519")
	g := geo.GeometryFromUserForwardPayloadLength(nike, 5000, true, 5)
	cmds := NewStorageReplicaCommands(sphinx.NewSphinx(g).Geometry(), nike)
	fuzzSeeds(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		checkFromBytes(t, cmds, data)
	})
}
