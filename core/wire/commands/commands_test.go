// commands_test.go - Tests for wire protocol commands.
// Copyright (C) 2017  David Anthony Stainton, Yawning Angel
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package commands

import (
	"testing"

	"github.com/stretchr/testify/require"

	ecdh "github.com/katzenpost/hpqc/nike/x25519"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/hpqc/sign/schemes"
	"github.com/katzenpost/hpqc/util"

	"github.com/katzenpost/katzenpost/core/sphinx"
	"github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
)

var testCertScheme = schemes.ByName("Ed25519")

func TestWTF(t *testing.T) {
	nike := ecdh.Scheme(rand.Reader)
	forwardPayloadLength := 123
	nrHops := 5

	geo := geo.GeometryFromUserForwardPayloadLength(nike, forwardPayloadLength, true, nrHops)
	s := sphinx.NewSphinx(geo)
	cmds := NewMixnetCommands(s.Geometry())
	require.NotNil(t, cmds)
}

func TestNoOp(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	nike := ecdh.Scheme(rand.Reader)
	forwardPayloadLength := 123
	nrHops := 5

	geo := geo.GeometryFromUserForwardPayloadLength(nike, forwardPayloadLength, true, nrHops)
	s := sphinx.NewSphinx(geo)
	cmds := NewMixnetCommands(s.Geometry())

	cmd := &NoOp{
		Cmds: cmds,
	}
	b := cmd.ToBytes()
	require.Len(b, cmds.maxMessageLenClientToServer, "NoOp: ToBytes() length")
	require.True(util.CtIsZero(b[cmdOverhead:]), "NoOp: ToBytes() padding must be zero")

	c, err := cmds.FromBytes(b)
	require.NoError(err, "NoOp: FromBytes() failed")
	require.IsType(cmd, c, "NoOp: FromBytes() invalid type")
}

func TestDisconnect(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	nike := ecdh.Scheme(rand.Reader)
	forwardPayloadLength := 123
	nrHops := 5

	geo := geo.GeometryFromUserForwardPayloadLength(nike, forwardPayloadLength, true, nrHops)
	s := sphinx.NewSphinx(geo)
	cmds := NewMixnetCommands(s.Geometry())

	cmd := &Disconnect{
		Cmds: cmds,
	}
	b := cmd.ToBytes()
	require.Len(b, cmds.maxMessageLenClientToServer, "Disconnect: ToBytes() length")
	require.True(util.CtIsZero(b[cmdOverhead:]), "Disconnect: ToBytes() padding must be zero")

	c, err := cmds.FromBytes(b)
	require.NoError(err, "Disconnect: FromBytes() failed")
	require.IsType(cmd, c, "Disconnect: FromBytes() invalid type")
}

func TestGetConsensus(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	nike := ecdh.Scheme(rand.Reader)
	forwardPayloadLength := 123
	nrHops := 5
	geo := geo.GeometryFromUserForwardPayloadLength(nike, forwardPayloadLength, true, nrHops)
	s := sphinx.NewSphinx(geo)
	cmds := NewMixnetCommands(s.Geometry())

	cmd := &GetConsensus{
		Epoch:              123,
		Cmds:               cmds,
		MixnetTransmission: false,
	}
	b := cmd.ToBytes()
	require.Equal(getConsensusLength+cmdOverhead, len(b), "GetConsensus: ToBytes() length")

	c, err := cmds.FromBytes(b)
	require.NoError(err, "GetConsensus: FromBytes() failed")
	require.IsType(cmd, c, "GetConsensus: FromBytes() invalid type")

	// Test with Mixnet Transmission. padding is expected.
	cmd.MixnetTransmission = true
	b = cmd.ToBytes()

	require.Len(b, cmds.maxMessageLenClientToServer, "GetConsensus without Mixnet: ToBytes() length")
	actualDataLength := cmdOverhead + getConsensusLength
	require.True(util.CtIsZero(b[actualDataLength:]), "GetConsensus without Mixnet: No padding expected")

	c, err = cmds.FromBytes(b)
	require.NoError(err, "GetConsensus without Mixnet: FromBytes() failed")
	require.IsType(cmd, c, "GetConsensus without Mixnet: FromBytes() invalid type")
}

func TestConsensus(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	cmd := &Consensus{
		Payload:   []byte("TANSTAFL: There's ain't no such thing as a free lunch."),
		ErrorCode: ConsensusOk,
	}
	b := cmd.ToBytes()
	require.Len(b, consensusBaseLength+len(cmd.Payload)+cmdOverhead, "GetConsensus: ToBytes() length")

	nike := ecdh.Scheme(rand.Reader)
	forwardPayloadLength := 123
	nrHops := 5
	geo := geo.GeometryFromUserForwardPayloadLength(nike, forwardPayloadLength, true, nrHops)
	s := sphinx.NewSphinx(geo)
	cmds := NewMixnetCommands(s.Geometry())

	c, err := cmds.FromBytes(b)
	require.NoError(err, "Consensus: FromBytes() failed")
	require.IsType(cmd, c, "Consensus: FromBytes() invalid type")
	d := c.(*Consensus)
	require.Equal(d.Payload, cmd.Payload)
	require.Equal(d.ErrorCode, cmd.ErrorCode)

	cmd.Payload = nil
	cmd.ErrorCode = ConsensusNotFound // Just set it to something non 0.
	b = cmd.ToBytes()
	require.Len(b, consensusBaseLength+len(cmd.Payload)+cmdOverhead, "GetConsensus: ToBytes() length")
	c, err = cmds.FromBytes(b)
	require.NoError(err, "Consensus: FromBytes() failed")
	require.IsType(cmd, c, "Consensus: FromBytes() invalid type")
	d = c.(*Consensus)
	require.Equal(d.Payload, cmd.Payload)
	require.Equal(d.ErrorCode, cmd.ErrorCode)
}

func TestSendRetrievePacket(t *testing.T) {
	t.Parallel()
	const payload = "A free man must be able to endure it when his fellow men act and live otherwise than he considers proper. He must free himself from the habit, just as soon as something does not please him, of calling for the police."

	require := require.New(t)

	nike := ecdh.Scheme(rand.Reader)
	forwardPayloadLength := len(payload)
	nrHops := 5

	geo := geo.GeometryFromUserForwardPayloadLength(nike, forwardPayloadLength, true, nrHops)
	s := sphinx.NewSphinx(geo)

	cmds := NewMixnetCommands(s.Geometry())

	packet := make([]byte, geo.PacketLength)
	copy(packet[:len(payload)], payload)

	cmd := &SendRetrievePacket{
		SphinxPacket: packet,
		Cmds:         cmds,
		Geo:          geo,
	}

	b := cmd.ToBytes()
	require.Len(b, cmds.maxMessageLenClientToServer)
	actualDataLength := cmdOverhead + len(packet)
	require.True(util.CtIsZero(b[actualDataLength:]))

	c, err := cmds.FromBytes(b)
	require.NoError(err)
	require.IsType(cmd, c)

	cmd2 := c.(*SendRetrievePacket)
	require.Equal([]byte(packet), cmd2.SphinxPacket)
}

func TestSendRetrievePacketReply(t *testing.T) {
	t.Parallel()
	const payload = "A free man must be able to endure it when his fellow men act and live otherwise than he considers proper. He must free himself from the habit, just as soon as something does not please him, of calling for the police."

	nike := ecdh.Scheme(rand.Reader)
	forwardPayloadLength := 1234
	nrHops := 5

	geo := geo.GeometryFromUserForwardPayloadLength(nike, forwardPayloadLength, true, nrHops)
	s := sphinx.NewSphinx(geo)

	cmds := NewMixnetCommands(s.Geometry())

	surbid := [constants.SURBIDLength]byte{}
	_, err := rand.Reader.Read(surbid[:])
	require.NoError(t, err)

	cmd := &SendRetrievePacketReply{
		SURBID:  surbid,
		Payload: []byte(payload),
		Cmds:    cmds,
		Geo:     geo,
	}

	b := cmd.ToBytes()
	require.Len(t, b, cmds.maxMessageLenServerToClient)
	actualDataLength := cmdOverhead + constants.SURBIDLength + len(payload)
	require.True(t, util.CtIsZero(b[actualDataLength:]))

	c, err := cmds.FromBytes(b)
	require.NoError(t, err)
	require.IsType(t, cmd, c)

	cmd2 := c.(*SendRetrievePacketReply)
	require.Equal(t, []byte(payload), cmd2.Payload)
}
