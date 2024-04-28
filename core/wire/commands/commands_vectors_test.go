// commands_vectors_test.go - Test vector tests for wire protocol commands.
// Copyright (C) 2019  David Stainton.
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
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	ecdh "github.com/katzenpost/hpqc/nike/x25519"

	"github.com/katzenpost/katzenpost/core/sphinx"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
)

const wireCommandsVectorsFile = "testdata/wire_commands_vectors.json"

const payload = "A free man must be able to endure it when his fellow men act and live otherwise than he considers proper. He must free himself from the habit, just as soon as something does not please him, of calling for the police."

type commandsTest struct {
	NoOp               string
	Disconnect         string
	SendPacketPayload  string
	SendPacket         string
	RetrieveMessageSeq uint32
	RetrieveMessage    string
	MessageEmpty       string
	MessageEmptySeq    uint32
	Message            string
	MessageHint        uint8
	MessageSeq         uint32
	MessagePayload     string
	MessageAck         string
	MessageAckHint     uint8
	MessageAckSeq      uint32
	MessageAckPayload  string
	GetConsensus       string
	GetConsensusEpoch  uint64
	Consensus          string
	ConsensusPayload   string
	ConsensusErrorCode uint8
}

func NoTestBuildCommandVectors(t *testing.T) {
	assert := assert.New(t)

	const (
		hint = 0x17
	)

	nike := ecdh.Scheme(rand.Reader)
	//forwardPayloadLength := len(payload) + (sphinx.SphinxPlaintextHeaderLength + 556)
	nrHops := 5

	//geo := geo.GeometryFromForwardPayloadLength(nike, forwardPayloadLength, nrHops)
	geo := geo.GeometryFromUserForwardPayloadLength(nike, len(payload), true, nrHops)
	cmds := &Commands{
		geo: geo,
	}

	noOp := NoOp{
		Cmds: cmds,
	}
	disconnect := &Disconnect{
		Cmds: cmds,
	}

	sendPacket := &SendPacket{SphinxPacket: []byte(payload), Cmds: cmds}

	var retrieveMessageSeq uint32 = 12345
	retrieveMessage := &RetrieveMessage{Sequence: retrieveMessageSeq, Cmds: cmds}

	var emptyMsgSeq uint32 = 9876
	messageEmpty := &MessageEmpty{
		Cmds:     cmds,
		Sequence: emptyMsgSeq,
	}

	msgPayload := make([]byte, cmds.geo.ForwardPayloadLength)
	_, err := rand.Read(msgPayload)
	assert.NoError(err)
	var msgSeq uint32 = 9876
	message := &Message{
		Cmds: cmds,
		Geo:  geo,

		QueueSizeHint: hint,
		Sequence:      msgSeq,
		Payload:       msgPayload[:geo.UserForwardPayloadLength],
	}

	ackPayload := make([]byte, cmds.geo.PayloadTagLength+cmds.geo.ForwardPayloadLength)
	_, err = rand.Read(ackPayload)
	assert.NoError(err)
	cmdMessageACK := &MessageACK{
		Geo:           geo,
		Cmds:          cmds,
		QueueSizeHint: hint,
		Sequence:      msgSeq,
		Payload:       ackPayload,
	}

	getConsensusEpoch := uint64(123)
	getConsensus := &GetConsensus{
		Epoch: getConsensusEpoch,
		Cmds:  cmds,
	}

	consensus := &Consensus{
		Payload:   []byte("TANSTAFL: There's ain't no such thing as a free lunch."),
		ErrorCode: ConsensusOk,
	}

	cmdsTest := commandsTest{
		NoOp:               hex.EncodeToString(noOp.ToBytes()),
		Disconnect:         hex.EncodeToString(disconnect.ToBytes()),
		SendPacketPayload:  hex.EncodeToString([]byte(payload)),
		SendPacket:         hex.EncodeToString(sendPacket.ToBytes()),
		RetrieveMessage:    hex.EncodeToString(retrieveMessage.ToBytes()),
		RetrieveMessageSeq: retrieveMessageSeq,
		MessageEmpty:       hex.EncodeToString(messageEmpty.ToBytes()),
		MessageEmptySeq:    emptyMsgSeq,
		MessageHint:        hint,
		MessageSeq:         msgSeq,
		MessagePayload:     hex.EncodeToString(msgPayload[:cmds.geo.UserForwardPayloadLength]),
		Message:            hex.EncodeToString(message.ToBytes()),
		MessageAck:         hex.EncodeToString(cmdMessageACK.ToBytes()),
		MessageAckHint:     hint,
		MessageAckSeq:      msgSeq,
		MessageAckPayload:  hex.EncodeToString(ackPayload),
		GetConsensus:       hex.EncodeToString(getConsensus.ToBytes()),
		GetConsensusEpoch:  getConsensusEpoch,
		Consensus:          hex.EncodeToString(consensus.ToBytes()),
		ConsensusPayload:   hex.EncodeToString(consensus.Payload),
		ConsensusErrorCode: consensus.ErrorCode,
	}

	serialized, err := json.Marshal(cmdsTest)
	assert.NoError(err)
	err = os.WriteFile(wireCommandsVectorsFile, serialized, 0644)
	assert.NoError(err)
}

func TestCommandVectors(t *testing.T) {
	assert := assert.New(t)

	serialized, err := os.ReadFile(wireCommandsVectorsFile)
	assert.NoError(err)
	cmdsTest := commandsTest{}
	err = json.Unmarshal(serialized, &cmdsTest)
	assert.NoError(err)

	nike := ecdh.Scheme(rand.Reader)

	nrHops := 5

	geo := geo.GeometryFromUserForwardPayloadLength(nike, len(payload), true, nrHops)
	s := sphinx.NewSphinx(geo)

	cmds := &Commands{
		geo: s.Geometry(),
	}

	noOpBytes, err := hex.DecodeString(cmdsTest.NoOp)
	assert.NoError(err)
	cmd, err := cmds.FromBytes(noOpBytes)
	assert.NoError(err)
	_, ok := cmd.(*NoOp)
	assert.True(ok)

	disconnectBytes, err := hex.DecodeString(cmdsTest.Disconnect)
	assert.NoError(err)
	cmd, err = cmds.FromBytes(disconnectBytes)
	assert.NoError(err)
	_, ok = cmd.(*Disconnect)
	assert.True(ok)

	sphinxPacket, err := hex.DecodeString(cmdsTest.SendPacketPayload)
	assert.NoError(err)
	sendPacketCommand, err := hex.DecodeString(cmdsTest.SendPacket)
	assert.NoError(err)
	sendPacket := &SendPacket{SphinxPacket: sphinxPacket, Cmds: cmds}
	sendPacketBytes := sendPacket.ToBytes()
	assert.Equal(sendPacketBytes[:len(sendPacketCommand)], sendPacketCommand)

	retrieveMessage := &RetrieveMessage{Sequence: cmdsTest.RetrieveMessageSeq, Cmds: cmds}
	retrieveMessageBytes := retrieveMessage.ToBytes()
	retrieveMessageWant, err := hex.DecodeString(cmdsTest.RetrieveMessage)
	assert.NoError(err)
	assert.Equal(retrieveMessageBytes[:len(retrieveMessageWant)], retrieveMessageWant)

	messageEmptyWant, err := hex.DecodeString(cmdsTest.MessageEmpty)
	assert.NoError(err)

	emptyMessage := &MessageEmpty{
		Cmds:     cmds,
		Sequence: cmdsTest.MessageEmptySeq,
	}
	emptyMessageCmd := emptyMessage.ToBytes()
	assert.Equal(emptyMessageCmd[:len(messageEmptyWant)], messageEmptyWant)

	messageWant, err := hex.DecodeString(cmdsTest.Message)
	assert.NoError(err)

	payload, err := hex.DecodeString(cmdsTest.MessagePayload)
	assert.NoError(err)

	message := &Message{
		Geo:           geo,
		Cmds:          cmds,
		QueueSizeHint: cmdsTest.MessageHint,
		Sequence:      cmdsTest.MessageSeq,
		Payload:       payload,
	}

	messageCmd := message.ToBytes()
	assert.Equal(messageCmd[:len(messageWant)], messageWant)

	messageAckWant, err := hex.DecodeString(cmdsTest.MessageAck)
	assert.NoError(err)

	ackPayload, err := hex.DecodeString(cmdsTest.MessageAckPayload)
	assert.NoError(err)
	messageAck := &MessageACK{
		Geo:  geo,
		Cmds: cmds,

		QueueSizeHint: cmdsTest.MessageAckHint,
		Sequence:      cmdsTest.MessageAckSeq,
		Payload:       ackPayload,
	}
	messageAckCmd := messageAck.ToBytes()
	assert.Equal(messageAckCmd[:len(messageAckWant)], messageAckWant)

	getConsensusWant, err := hex.DecodeString(cmdsTest.GetConsensus)
	assert.NoError(err)
	getConsensus := &GetConsensus{
		Epoch: cmdsTest.GetConsensusEpoch,
		Cmds:  cmds,
	}
	getConsensusCmd := getConsensus.ToBytes()
	assert.Equal(getConsensusCmd[:len(getConsensusWant)], getConsensusWant)

	consensusWant, err := hex.DecodeString(cmdsTest.Consensus)
	assert.NoError(err)
	consensusPayload, err := hex.DecodeString(cmdsTest.ConsensusPayload)
	assert.NoError(err)
	consensus := &Consensus{
		Payload:   consensusPayload,
		ErrorCode: cmdsTest.ConsensusErrorCode,
	}
	consensusCmd := consensus.ToBytes()
	assert.Equal(consensusCmd, consensusWant)
}
