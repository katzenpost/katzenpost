//go:build fuzz

// SPDX-License-Identifier: AGPL-3.0-only

package sphinx

import (
	"testing"

	"github.com/katzenpost/katzenpost/fuzz/seed"

	nikeSchemes "github.com/katzenpost/hpqc/nike/schemes"

	"github.com/katzenpost/katzenpost/core/sphinx/geo"
)

func FuzzUnwrapNike(f *testing.F) {
	scheme := nikeSchemes.ByName("x25519")
	g := geo.GeometryFromUserForwardPayloadLength(scheme, 2000, true, 5)
	s := NewSphinx(g)
	_, privKey, err := scheme.GenerateKeyPair()
	if err != nil {
		f.Fatal(err)
	}

	f.Add([]byte(nil))
	f.Add([]byte{})
	f.Add(make([]byte, 2))
	f.Add(make([]byte, g.HeaderLength))
	f.Add(make([]byte, g.PacketLength))
	f.Fuzz(func(t *testing.T, data []byte) {
		if seed.Export(data) {
			return
		}
		payload, _, cmds, err := s.Unwrap(privKey, data)
		if err == nil && payload == nil && cmds == nil {
			t.Fatal("Unwrap returned nil payload, nil commands and nil error")
		}
	})
}

func FuzzNewPacketFromSURB(f *testing.F) {
	scheme := nikeSchemes.ByName("x25519")
	g := geo.GeometryFromUserForwardPayloadLength(scheme, 2000, true, 5)
	s := NewSphinx(g)
	payload := make([]byte, g.ForwardPayloadLength)

	f.Add([]byte(nil))
	f.Add([]byte{})
	f.Add(make([]byte, 2))
	f.Add(make([]byte, g.SURBLength))
	f.Fuzz(func(t *testing.T, data []byte) {
		if seed.Export(data) {
			return
		}
		pkt, id, err := s.NewPacketFromSURB(data, payload)
		if err == nil && (pkt == nil || id == nil) {
			t.Fatal("NewPacketFromSURB returned nil packet or nil id and nil error")
		}
	})
}
