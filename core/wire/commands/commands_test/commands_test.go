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

package commands_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/crypto/cert"
	"github.com/katzenpost/katzenpost/core/crypto/nike/ecdh"
	"github.com/katzenpost/katzenpost/core/crypto/rand"
	"github.com/katzenpost/katzenpost/core/sphinx"
	"github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/wire/commands"
)

func TestNoOp(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	nike := ecdh.NewEcdhNike(rand.Reader)
	forwardPayloadLength := 123
	nrHops := 5

	geo := geo.GeometryFromUserForwardPayloadLength(nike, forwardPayloadLength, true, nrHops)
	s := sphinx.NewSphinx(geo)
	cmds := &commands.Commands{
		Geo: s.Geometry(),
	}

	cmd := &commands.NoOp{}
	b := cmd.ToBytes()
	require.Equal(commands.CmdOverhead, len(b), "NoOp: ToBytes() length")

	c, err := cmds.FromBytes(b)
	require.NoError(err, "NoOp: FromBytes() failed")
	require.IsType(cmd, c, "NoOp: FromBytes() invalid type")
}

func TestDisconnect(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	cmd := &commands.Disconnect{}
	b := cmd.ToBytes()
	require.Equal(commands.CmdOverhead, len(b), "Disconnect: ToBytes() length")

	nike := ecdh.NewEcdhNike(rand.Reader)
	forwardPayloadLength := 123
	nrHops := 5

	geo := geo.GeometryFromUserForwardPayloadLength(nike, forwardPayloadLength, true, nrHops)
	s := sphinx.NewSphinx(geo)
	cmds := &commands.Commands{
		Geo: s.Geometry(),
	}

	c, err := cmds.FromBytes(b)
	require.NoError(err, "Disconnect: FromBytes() failed")
	require.IsType(cmd, c, "Disconnect: FromBytes() invalid type")
}

func TestSendPacket(t *testing.T) {
	t.Parallel()
	const payload = "A free man must be able to endure it when his fellow men act and live otherwise than he considers proper. He must free himself from the habit, just as soon as something does not please him, of calling for the police."

	require := require.New(t)

	cmd := &commands.SendPacket{SphinxPacket: []byte(payload)}
	b := cmd.ToBytes()
	require.Equal(commands.CmdOverhead+len(payload), len(b), "SendPacket: ToBytes() length")

	nike := ecdh.NewEcdhNike(rand.Reader)
	forwardPayloadLength := 123
	nrHops := 5
	geo := geo.GeometryFromUserForwardPayloadLength(nike, forwardPayloadLength, true, nrHops)
	s := sphinx.NewSphinx(geo)
	cmds := &commands.Commands{
		Geo: s.Geometry(),
	}

	c, err := cmds.FromBytes(b)
	require.NoError(err, "SendPacket: FromBytes() failed")
	require.IsType(cmd, c, "SendPacket: FromBytes() invalid type")

	cmd = c.(*commands.SendPacket)
	require.Equal([]byte(payload), cmd.SphinxPacket, "SendPacket: FromBytes() SphinxPacket")
}

func TestRetrieveMessage(t *testing.T) {
	t.Parallel()
	const seq = 0xbeefbeef

	require := require.New(t)

	cmd := &commands.RetrieveMessage{Sequence: seq}
	b := cmd.ToBytes()
	require.Equal(commands.CmdOverhead+4, len(b), "RetrieveMessage: ToBytes() length")

	nike := ecdh.NewEcdhNike(rand.Reader)
	forwardPayloadLength := 123
	nrHops := 5
	geo := geo.GeometryFromUserForwardPayloadLength(nike, forwardPayloadLength, true, nrHops)
	s := sphinx.NewSphinx(geo)
	cmds := &commands.Commands{
		Geo: s.Geometry(),
	}

	c, err := cmds.FromBytes(b)
	require.NoError(err, "RetrieveMessage: FromBytes() failed")
	require.IsType(cmd, c, "RetrieveMessage: FromBytes() invalid type")

	cmd = c.(*commands.RetrieveMessage)
	require.Equal(uint32(seq), cmd.Sequence, "RetrieveMessage: FromBytes() Sequence")
}

func TestMessage(t *testing.T) {
	t.Parallel()

	nike := ecdh.NewEcdhNike(rand.Reader)
	forwardPayloadLength := 2000
	nrHops := 5
	geo := geo.GeometryFromUserForwardPayloadLength(nike, forwardPayloadLength, true, nrHops)
	cmds := &commands.Commands{
		Geo: geo,
	}

	var expectedLen = commands.CmdOverhead + cmds.MessageEmptyLength()
	const (
		hint = 0x17
		seq  = 0xa5a5a5a5
	)

	require := require.New(t)

	// Generate the payload.
	payload := make([]byte, cmds.Geo.ForwardPayloadLength)
	_, err := rand.Reader.Read(payload)
	require.NoError(err, "Message: failed to generate payload")

	// MessageEmpty
	cmdEmpty := &commands.MessageEmpty{
		Cmds:     cmds,
		Sequence: seq,
	}
	b := cmdEmpty.ToBytes()
	require.Equal(expectedLen, len(b), "MessageEmpty: ToBytes() length")

	c, err := cmds.FromBytes(b)
	require.NoError(err, "MessageEmpty: FromBytes() failed")
	require.IsType(cmdEmpty, c, "MessageEmpty: FromBytes() invalid type")

	cmdEmpty = c.(*commands.MessageEmpty)
	require.Equal(uint32(seq), cmdEmpty.Sequence, "MessageEmpty: FromBytes() Sequence")

	// Message
	msgPayload := payload[:cmds.Geo.UserForwardPayloadLength]
	cmdMessage := &commands.Message{
		Geo:  geo,
		Cmds: cmds,

		QueueSizeHint: hint,
		Sequence:      seq,
		Payload:       msgPayload,
	}
	b = cmdMessage.ToBytes()
	require.Equal(expectedLen, len(b), "Message: ToBytes() length")

	c, err = cmds.FromBytes(b)
	require.NoError(err, "Message: FromBytes() failed")
	require.IsType(cmdMessage, c, "Message: FromBytes() invalid type")

	cmdMessage = c.(*commands.Message)
	require.Equal(uint8(hint), cmdMessage.QueueSizeHint, "Message: FromBytes() QueueSizeHint")
	require.Equal(uint32(seq), cmdMessage.Sequence, "Message: FromBytes() Sequence")
	require.Equal(msgPayload, cmdMessage.Payload, "Message: FromBytes() Payload")

	// MessageACK
	ackPayload := make([]byte, cmds.Geo.PayloadTagLength+cmds.Geo.ForwardPayloadLength)
	_, err = rand.Reader.Read(ackPayload)
	require.NoError(err, "Message: failed to generate ACK payload")
	id := make([]byte, constants.SURBIDLength)
	_, err = rand.Reader.Read(id[:])
	require.NoError(err, "MessageACK: Failed to generate ID")

	cmdMessageACK := &commands.MessageACK{
		Geo: geo,

		QueueSizeHint: hint,
		Sequence:      seq,
		Payload:       ackPayload,
	}
	copy(cmdMessageACK.ID[:], id[:])
	b = cmdMessageACK.ToBytes()
	require.Equal(expectedLen, len(b), "MessageACK: ToBytes() length")

	c, err = cmds.FromBytes(b)
	require.NoError(err, "MessageACK: FromBytes() failed")
	require.IsType(cmdMessageACK, c, "MessageACK: FromBytes() invalid type")

	cmdMessageACK = c.(*commands.MessageACK)
	require.Equal(uint8(hint), cmdMessageACK.QueueSizeHint, "MessageACK: FromBytes() QueueSizeHint")
	require.Equal(uint32(seq), cmdMessageACK.Sequence, "MessageACK: FromBytes() Sequence")
	require.Equal(id[:], cmdMessageACK.ID[:], "MessageACK: FromBytes() ID")
	require.Equal(ackPayload, cmdMessageACK.Payload, "MessageACK: FromBytes() Payload")
}

func TestGetConsensus(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	cmd := &commands.GetConsensus{
		Epoch: 123,
	}
	b := cmd.ToBytes()
	require.Equal(commands.GetConsensusLength+commands.CmdOverhead, len(b), "GetConsensus: ToBytes() length")

	nike := ecdh.NewEcdhNike(rand.Reader)
	forwardPayloadLength := 123
	nrHops := 5
	geo := geo.GeometryFromUserForwardPayloadLength(nike, forwardPayloadLength, true, nrHops)
	s := sphinx.NewSphinx(geo)
	cmds := &commands.Commands{
		Geo: s.Geometry(),
	}

	c, err := cmds.FromBytes(b)
	require.NoError(err, "GetConsensus: FromBytes() failed")
	require.IsType(cmd, c, "GetConsensus: FromBytes() invalid type")
}

func TestConsensus(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	cmd := &commands.Consensus{
		Payload:   []byte("TANSTAFL: There's ain't no such thing as a free lunch."),
		ErrorCode: commands.ConsensusOk,
	}
	b := cmd.ToBytes()
	require.Len(b, commands.ConsensusBaseLength+len(cmd.Payload)+commands.CmdOverhead, "GetConsensus: ToBytes() length")

	nike := ecdh.NewEcdhNike(rand.Reader)
	forwardPayloadLength := 123
	nrHops := 5
	geo := geo.GeometryFromUserForwardPayloadLength(nike, forwardPayloadLength, true, nrHops)
	s := sphinx.NewSphinx(geo)
	cmds := &commands.Commands{
		Geo: s.Geometry(),
	}

	c, err := cmds.FromBytes(b)
	require.NoError(err, "Consensus: FromBytes() failed")
	require.IsType(cmd, c, "Consensus: FromBytes() invalid type")
	d := c.(*commands.Consensus)
	require.Equal(d.Payload, cmd.Payload)
	require.Equal(d.ErrorCode, cmd.ErrorCode)

	cmd.Payload = nil
	cmd.ErrorCode = commands.ConsensusNotFound // Just set it to something non 0.
	b = cmd.ToBytes()
	require.Len(b, commands.ConsensusBaseLength+len(cmd.Payload)+commands.CmdOverhead, "GetConsensus: ToBytes() length")
	c, err = cmds.FromBytes(b)
	require.NoError(err, "Consensus: FromBytes() failed")
	require.IsType(cmd, c, "Consensus: FromBytes() invalid type")
	d = c.(*commands.Consensus)
	require.Equal(d.Payload, cmd.Payload)
	require.Equal(d.ErrorCode, cmd.ErrorCode)
}

func TestPostDescriptor(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	cmd := &commands.PostDescriptor{
		Epoch:   0xdeadbabecafebeef,
		Payload: []byte("This is my descriptor."),
	}
	b := cmd.ToBytes()
	require.Equal(commands.PostDescriptorLength+len(cmd.Payload)+commands.CmdOverhead, len(b), "PostDescriptor: ToBytes() length")

	nike := ecdh.NewEcdhNike(rand.Reader)
	forwardPayloadLength := 123
	nrHops := 5

	geo := geo.GeometryFromUserForwardPayloadLength(nike, forwardPayloadLength, true, nrHops)
	s := sphinx.NewSphinx(geo)

	cmds := &commands.Commands{
		Geo: s.Geometry(),
	}

	c, err := cmds.FromBytes(b)
	require.NoError(err, "PostDescriptor: FromBytes() failed")
	require.IsType(cmd, c, "PostDescriptor: FromBytes() invalid type")
	d := c.(*commands.PostDescriptor)
	require.Equal(d.Epoch, cmd.Epoch)
	require.Equal(d.Payload, cmd.Payload)
}

func TestPostDescriptorStatus(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	cmd := &commands.PostDescriptorStatus{
		ErrorCode: 23,
	}
	b := cmd.ToBytes()
	require.Len(b, commands.PostDescriptorStatusLength+commands.CmdOverhead, "PostDescriptorStatus: ToBytes() length")

	nike := ecdh.NewEcdhNike(rand.Reader)
	forwardPayloadLength := 123
	nrHops := 5

	geo := geo.GeometryFromUserForwardPayloadLength(nike, forwardPayloadLength, true, nrHops)
	s := sphinx.NewSphinx(geo)

	cmds := &commands.Commands{
		Geo: s.Geometry(),
	}

	c, err := cmds.FromBytes(b)
	require.NoError(err, "PostDescriptorStatus: FromBytes() failed")
	require.IsType(cmd, c, "PostDescriptorStatus: FromBytes() invalid type")
	d := c.(*commands.PostDescriptorStatus)
	require.Equal(d.ErrorCode, cmd.ErrorCode)
}

func TestGetVote(t *testing.T) {
	t.Parallel()
	require := require.New(t)
	_, alicePub := cert.Scheme.NewKeypair()

	cmd := &commands.GetVote{
		Epoch:     123,
		PublicKey: alicePub,
	}
	b := cmd.ToBytes()
	require.Equal(commands.VoteOverhead+commands.CmdOverhead, len(b), "GetVote: ToBytes() length")

	nike := ecdh.NewEcdhNike(rand.Reader)
	forwardPayloadLength := 123
	nrHops := 5

	geo := geo.GeometryFromUserForwardPayloadLength(nike, forwardPayloadLength, true, nrHops)
	s := sphinx.NewSphinx(geo)

	cmds := &commands.Commands{
		Geo: s.Geometry(),
	}

	c, err := cmds.FromBytes(b)
	require.NoError(err, "GetVote: FromBytes() failed")
	require.IsType(cmd, c, "GetVote: FromBytes() invalid type")
}

func TestVote(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	_, alicePub := cert.Scheme.NewKeypair()
	cmd := &commands.Vote{
		Epoch:     3141,
		PublicKey: alicePub,
		Payload:   []byte{1, 2, 3, 4},
	}
	b := cmd.ToBytes()
	require.Len(b, commands.CmdOverhead+commands.VoteOverhead+len(cmd.Payload), "Vote: ToBytes() length")

	nike := ecdh.NewEcdhNike(rand.Reader)
	forwardPayloadLength := 123
	nrHops := 5

	geo := geo.GeometryFromUserForwardPayloadLength(nike, forwardPayloadLength, true, nrHops)
	s := sphinx.NewSphinx(geo)

	cmds := &commands.Commands{
		Geo: s.Geometry(),
	}

	c, err := cmds.FromBytes(b)
	require.NoError(err, "Vote: FromBytes() failed")
	require.IsType(cmd, c, "Vote: FromBytes() invalid type")
	d := c.(*commands.Vote)
	require.Equal(d.Epoch, cmd.Epoch)
	require.Equal(d.PublicKey.Bytes(), cmd.PublicKey.Bytes())
	require.Equal(d.Payload, cmd.Payload)
}

func TestVoteStatus(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	cmd := &commands.VoteStatus{
		ErrorCode: 23,
	}
	b := cmd.ToBytes()
	require.Len(b, commands.VoteStatusLength+commands.CmdOverhead, "VoteStatus: ToBytes() length")

	nike := ecdh.NewEcdhNike(rand.Reader)
	forwardPayloadLength := 123
	nrHops := 5

	geo := geo.GeometryFromUserForwardPayloadLength(nike, forwardPayloadLength, true, nrHops)
	s := sphinx.NewSphinx(geo)

	cmds := &commands.Commands{
		Geo: s.Geometry(),
	}

	c, err := cmds.FromBytes(b)
	require.NoError(err, "VoteStatus: FromBytes() failed")
	require.IsType(cmd, c, "VoteStatus: FromBytes() invalid type")
	d := c.(*commands.VoteStatus)
	require.Equal(d.ErrorCode, cmd.ErrorCode)
}

func TestReveal(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	_, alicePub := cert.Scheme.NewKeypair()
	digest := make([]byte, 32)
	for i := 0; i < 32; i++ {
		digest[i] = uint8(i)
	}
	cmd := &commands.Reveal{
		Epoch:     3141,
		PublicKey: alicePub,
		Payload:   digest,
	}
	b := cmd.ToBytes()
	require.Len(b, commands.CmdOverhead+commands.RevealOverhead+32, "Reveal: ToBytes() length")

	nike := ecdh.NewEcdhNike(rand.Reader)
	forwardPayloadLength := 123
	nrHops := 5

	geo := geo.GeometryFromUserForwardPayloadLength(nike, forwardPayloadLength, true, nrHops)
	s := sphinx.NewSphinx(geo)

	cmds := &commands.Commands{
		Geo: s.Geometry(),
	}

	c, err := cmds.FromBytes(b)
	require.NoError(err, "Reveal: FromBytes() failed")
	require.IsType(cmd, c, "Reveal: FromBytes() invalid type")
	d := c.(*commands.Reveal)
	require.Equal(d.Epoch, cmd.Epoch)
	require.Equal(d.PublicKey.Bytes(), cmd.PublicKey.Bytes())
	require.Equal(d.Payload, cmd.Payload)
}

func TestRevealtatus(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	cmd := &commands.RevealStatus{
		ErrorCode: 23,
	}
	b := cmd.ToBytes()
	require.Len(b, commands.RevealStatusLength+commands.CmdOverhead, "RevealStatus: ToBytes() length")

	nike := ecdh.NewEcdhNike(rand.Reader)
	forwardPayloadLength := 123
	nrHops := 5
	geo := geo.GeometryFromUserForwardPayloadLength(nike, forwardPayloadLength, true, nrHops)
	s := sphinx.NewSphinx(geo)
	cmds := &commands.Commands{
		Geo: s.Geometry(),
	}

	c, err := cmds.FromBytes(b)
	require.NoError(err, "RevealStatus: FromBytes() failed")
	require.IsType(cmd, c, "RevealStatus: FromBytes() invalid type")
	d := c.(*commands.RevealStatus)
	require.Equal(d.ErrorCode, cmd.ErrorCode)
}

func TestCert(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	_, alicePub := cert.Scheme.NewKeypair()
	cmd := &commands.Cert{
		Epoch:     3141,
		PublicKey: alicePub,
		Payload:   []byte{1, 2, 3, 4},
	}
	b := cmd.ToBytes()
	require.Len(b, commands.CmdOverhead+commands.CertOverhead+len(cmd.Payload), "Cert: ToBytes() length")

	nike := ecdh.NewEcdhNike(rand.Reader)
	forwardPayloadLength := 123
	nrHops := 5

	geo := geo.GeometryFromUserForwardPayloadLength(nike, forwardPayloadLength, true, nrHops)
	s := sphinx.NewSphinx(geo)

	cmds := &commands.Commands{
		Geo: s.Geometry(),
	}

	c, err := cmds.FromBytes(b)
	require.NoError(err, "Reveal: FromBytes() failed")
	require.IsType(cmd, c, "Reveal: FromBytes() invalid type")
	d := c.(*commands.Cert)
	require.Equal(d.Epoch, cmd.Epoch)
	require.Equal(d.PublicKey.Bytes(), cmd.PublicKey.Bytes())
	require.Equal(d.Payload, cmd.Payload)
}

func TestCertStatus(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	cmd := &commands.CertStatus{
		ErrorCode: 14,
	}
	b := cmd.ToBytes()
	require.Len(b, commands.CertStatusLength+commands.CmdOverhead, "CertStatus: ToBytes() length")

	nike := ecdh.NewEcdhNike(rand.Reader)
	forwardPayloadLength := 123
	nrHops := 5
	geo := geo.GeometryFromUserForwardPayloadLength(nike, forwardPayloadLength, true, nrHops)
	s := sphinx.NewSphinx(geo)
	cmds := &commands.Commands{
		Geo: s.Geometry(),
	}

	c, err := cmds.FromBytes(b)
	require.NoError(err, "CertStatus: FromBytes() failed")
	require.IsType(cmd, c, "CertStatus: FromBytes() invalid type")
	d := c.(*commands.CertStatus)
	require.Equal(d.ErrorCode, cmd.ErrorCode)
}

func TestSig(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	_, alicePub := cert.Scheme.NewKeypair()
	cmd := &commands.Sig{
		Epoch:     3141,
		PublicKey: alicePub,
		Payload:   []byte{1, 2, 3, 4},
	}
	b := cmd.ToBytes()
	require.Len(b, commands.CmdOverhead+commands.SigOverhead+len(cmd.Payload), "Sig: ToBytes() length")

	nike := ecdh.NewEcdhNike(rand.Reader)
	forwardPayloadLength := 123
	nrHops := 5

	geo := geo.GeometryFromUserForwardPayloadLength(nike, forwardPayloadLength, true, nrHops)
	s := sphinx.NewSphinx(geo)

	cmds := &commands.Commands{
		Geo: s.Geometry(),
	}

	c, err := cmds.FromBytes(b)
	require.NoError(err, "Sig: FromBytes() failed")
	require.IsType(cmd, c, "Sig: FromBytes() invalid type")
	d := c.(*commands.Sig)
	require.Equal(d.Epoch, cmd.Epoch)
	require.Equal(d.PublicKey.Bytes(), cmd.PublicKey.Bytes())
	require.Equal(d.Payload, cmd.Payload)
}

func TestSigStatus(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	cmd := &commands.SigStatus{
		ErrorCode: 23,
	}
	b := cmd.ToBytes()
	require.Len(b, commands.RevealStatusLength+commands.CmdOverhead, "SigStatus: ToBytes() length")

	nike := ecdh.NewEcdhNike(rand.Reader)
	forwardPayloadLength := 123
	nrHops := 5
	geo := geo.GeometryFromUserForwardPayloadLength(nike, forwardPayloadLength, true, nrHops)
	s := sphinx.NewSphinx(geo)
	cmds := &commands.Commands{
		Geo: s.Geometry(),
	}

	c, err := cmds.FromBytes(b)
	require.NoError(err, "SigStatus: FromBytes() failed")
	require.IsType(cmd, c, "SigStatus: FromBytes() invalid type")
	d := c.(*commands.SigStatus)
	require.Equal(d.ErrorCode, cmd.ErrorCode)
}
