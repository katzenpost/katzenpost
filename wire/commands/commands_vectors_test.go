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
	"io/ioutil"
	"testing"

	"github.com/katzenpost/core/constants"
	"github.com/katzenpost/core/sphinx"
	"github.com/stretchr/testify/assert"
	"github.com/ugorji/go/codec"
)

const wireCommandsVectorsFile = "testdata/wire_commands_vectors.json"

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

func TestBuildCommandVectors(t *testing.T) {
	assert := assert.New(t)

	noOp := NoOp{}
	disconnect := &Disconnect{}

	const payload = "A free man must be able to endure it when his fellow men act and live otherwise than he considers proper. He must free himself from the habit, just as soon as something does not please him, of calling for the police."
	sendPacket := &SendPacket{SphinxPacket: []byte(payload)}

	var retrieveMessageSeq uint32 = 12345
	retrieveMessage := &RetrieveMessage{Sequence: retrieveMessageSeq}

	const (
		// All packet lengths are currently normalized.
		expectedLen = cmdOverhead + messageEmptyLength
		hint        = 0x17
	)

	var emptyMsgSeq uint32 = 9876
	messageEmpty := &MessageEmpty{Sequence: emptyMsgSeq}

	msgPayload := make([]byte, constants.ForwardPayloadLength)
	_, err := rand.Read(msgPayload)
	assert.NoError(err)
	var msgSeq uint32 = 9876
	message := &Message{
		QueueSizeHint: hint,
		Sequence:      msgSeq,
		Payload:       msgPayload[:constants.UserForwardPayloadLength],
	}

	ackPayload := make([]byte, sphinx.PayloadTagLength+constants.ForwardPayloadLength)
	_, err = rand.Read(ackPayload)
	assert.NoError(err)
	cmdMessageACK := &MessageACK{
		QueueSizeHint: hint,
		Sequence:      msgSeq,
		Payload:       ackPayload,
	}

	getConsensusEpoch := uint64(123)
	getConsensus := &GetConsensus{
		Epoch: getConsensusEpoch,
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
		MessagePayload:     hex.EncodeToString(msgPayload[:constants.UserForwardPayloadLength]),
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

	serialized := []byte{}
	handle := new(codec.JsonHandle)
	handle.Indent = 4
	enc := codec.NewEncoderBytes(&serialized, handle)
	err = enc.Encode(cmdsTest)
	assert.NoError(err)
	err = ioutil.WriteFile(wireCommandsVectorsFile, serialized, 0644)
	assert.NoError(err)
}

func TestCommandVectors(t *testing.T) {
	assert := assert.New(t)

	serialized, err := ioutil.ReadFile(wireCommandsVectorsFile)
	assert.NoError(err)
	decoder := codec.NewDecoderBytes(serialized, new(codec.JsonHandle))
	cmdsTest := commandsTest{}
	err = decoder.Decode(&cmdsTest)
	assert.NoError(err)

	noOpBytes, err := hex.DecodeString(cmdsTest.NoOp)
	assert.NoError(err)
	cmd, err := FromBytes(noOpBytes)
	assert.NoError(err)
	_, ok := cmd.(*NoOp)
	assert.True(ok)

	disconnectBytes, err := hex.DecodeString(cmdsTest.Disconnect)
	assert.NoError(err)
	cmd, err = FromBytes(disconnectBytes)
	assert.NoError(err)
	_, ok = cmd.(*Disconnect)
	assert.True(ok)

	sphinxPacket, err := hex.DecodeString(cmdsTest.SendPacketPayload)
	assert.NoError(err)
	sendPacketCommand, err := hex.DecodeString(cmdsTest.SendPacket)
	assert.NoError(err)
	sendPacket := &SendPacket{SphinxPacket: sphinxPacket}
	sendPacketBytes := sendPacket.ToBytes()
	assert.Equal(sendPacketBytes, sendPacketCommand)

	retrieveMessage := &RetrieveMessage{Sequence: cmdsTest.RetrieveMessageSeq}
	retrieveMessageBytes := retrieveMessage.ToBytes()
	retrieveMessageWant, err := hex.DecodeString(cmdsTest.RetrieveMessage)
	assert.NoError(err)
	assert.Equal(retrieveMessageBytes, retrieveMessageWant)

	messageEmptyWant, err := hex.DecodeString(cmdsTest.MessageEmpty)
	assert.NoError(err)
	emptyMessage := &MessageEmpty{Sequence: cmdsTest.MessageEmptySeq}
	emptyMessageCmd := emptyMessage.ToBytes()
	assert.Equal(emptyMessageCmd, messageEmptyWant)

	messageWant, err := hex.DecodeString(cmdsTest.Message)
	assert.NoError(err)
	payload, err := hex.DecodeString(cmdsTest.MessagePayload)
	assert.NoError(err)
	message := &Message{
		QueueSizeHint: cmdsTest.MessageHint,
		Sequence:      cmdsTest.MessageSeq,
		Payload:       payload,
	}
	messageCmd := message.ToBytes()
	assert.Equal(messageCmd, messageWant)

	messageAckWant, err := hex.DecodeString(cmdsTest.MessageAck)
	assert.NoError(err)
	ackPayload, err := hex.DecodeString(cmdsTest.MessageAckPayload)
	assert.NoError(err)
	messageAck := &MessageACK{
		QueueSizeHint: cmdsTest.MessageAckHint,
		Sequence:      cmdsTest.MessageAckSeq,
		Payload:       ackPayload,
	}
	messageAckCmd := messageAck.ToBytes()
	assert.Equal(messageAckCmd, messageAckWant)

	getConsensusWant, err := hex.DecodeString(cmdsTest.GetConsensus)
	assert.NoError(err)
	getConsensus := &GetConsensus{
		Epoch: cmdsTest.GetConsensusEpoch,
	}
	getConsensusCmd := getConsensus.ToBytes()
	assert.Equal(getConsensusCmd, getConsensusWant)

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
