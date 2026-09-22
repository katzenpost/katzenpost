//go:build fuzz

// SPDX-License-Identifier: AGPL-3.0-only

package commands

import (
	"testing"

	nikeSchemes "github.com/katzenpost/hpqc/nike/schemes"

	"github.com/katzenpost/katzenpost/core/sphinx/geo"
)

func FuzzRoutingCommandsFromBytes(f *testing.F) {
	g := geo.GeometryFromUserForwardPayloadLength(nikeSchemes.ByName("x25519"), 2000, true, 5)
	f.Add([]byte(nil))
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add([]byte{byte(nextNodeHop)})
	f.Add([]byte{byte(recipient)})
	f.Add([]byte{byte(surbReply)})
	f.Add([]byte{byte(nodeDelay), 0, 0, 0, 0})
	f.Add(make([]byte, 256))
	f.Fuzz(func(t *testing.T, data []byte) {
		cmd, rest, err := FromBytes(data, g)
		if err != nil {
			return
		}
		if len(rest) > len(data) {
			t.Fatal("FromBytes returned more remaining bytes than input")
		}
		if cmd == nil {
			return
		}
		reCmd, reRest, reErr := FromBytes(cmd.ToBytes(nil), g)
		if reErr != nil {
			t.Fatalf("re-encoded routing command failed to parse: %v", reErr)
		}
		if reCmd == nil {
			t.Fatal("re-encoded routing command parsed to nil")
		}
		_ = reRest
	})
}
