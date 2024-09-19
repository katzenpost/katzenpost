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
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
)

var testCertScheme = schemes.ByName("Ed25519")

func TestNoOp(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	nike := ecdh.Scheme(rand.Reader)
	forwardPayloadLength := 123
	nrHops := 5

	geo := geo.GeometryFromUserForwardPayloadLength(nike, forwardPayloadLength, true, nrHops)
	s := sphinx.NewSphinx(geo)
	cmds := NewCommands(s.Geometry(), testCertScheme)

	cmd := &NoOp{
		Cmds: cmds,
	}
	b := cmd.ToBytes()
	require.Len(b, cmds.maxMessageLen(cmd), "NoOp: ToBytes() length")
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
	cmds := NewCommands(s.Geometry(), testCertScheme)

	cmd := &Disconnect{
		Cmds: cmds,
	}
	b := cmd.ToBytes()
	require.Len(b, cmds.maxMessageLen(cmd), "Disconnect: ToBytes() length")
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
	cmds := NewCommands(s.Geometry(), testCertScheme)

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

	require.Len(b, cmds.maxMessageLen(cmd), "GetConsensus without Mixnet: ToBytes() length")
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
	cmds := NewCommands(s.Geometry(), testCertScheme)

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
