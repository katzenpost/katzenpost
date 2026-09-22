// SPDX-License-Identifier: AGPL-3.0-only

package commands

import (
	"testing"

	nikeSchemes "github.com/katzenpost/hpqc/nike/schemes"

	"github.com/katzenpost/katzenpost/core/sphinx/geo"
)

func TestSendRetrievePacketRejectsWrongLength(t *testing.T) {
	nike := nikeSchemes.ByName("x25519")
	g := geo.GeometryFromUserForwardPayloadLength(nike, 2000, true, 5)
	cmds := NewMixnetCommands(g)

	if _, err := sendRetrievePacketFromBytes(make([]byte, g.PacketLength-1), cmds); err == nil {
		t.Fatal("short SphinxPacket accepted")
	}
	if _, err := sendRetrievePacketFromBytes(make([]byte, g.PacketLength+1), cmds); err == nil {
		t.Fatal("long SphinxPacket accepted")
	}
	if _, err := sendRetrievePacketFromBytes(make([]byte, g.PacketLength), cmds); err != nil {
		t.Fatalf("correct-length SphinxPacket rejected: %v", err)
	}
}
