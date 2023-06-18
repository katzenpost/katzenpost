// commands_test.go - Tests for reunion protocol commands.
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
	"crypto/sha256"
	"testing"

	"github.com/katzenpost/katzenpost/reunion/crypto"
	"github.com/stretchr/testify/require"
)

func fillRand(require *require.Assertions, b []byte) {
	_, err := rand.Read(b)
	require.NoError(err, "failed to randomize buffer")
}

func TestFetchStateCommand(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	cmd := new(FetchState)
	cmd.Epoch = 1234
	cmd.T1Hash = [sha256.Size]byte{}
	fillRand(require, cmd.T1Hash[:])

	b := cmd.ToBytes()
	require.Equal(len(b), fetchStateLength)

	c, err := FromBytes(b)
	require.NoError(err)
	require.IsType(cmd, c)
	cmd2 := c.(*FetchState)
	require.Equal(cmd.Epoch, cmd2.Epoch)
	require.Equal(cmd.T1Hash[:], cmd2.T1Hash[:])
}

func TestStateResponseCommand(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	cmd := new(StateResponse)
	cmd.ErrorCode = 123
	cmd.Truncated = true
	cmd.LeftOverChunksHint = 332
	cmd.Payload = make([]byte, crypto.PayloadSize)
	b := cmd.ToBytes()
	require.Equal(len(b), stateResponseLength)

	c, err := FromBytes(b)
	require.NoError(err)
	require.IsType(cmd, c)
	cmd2 := c.(*StateResponse)
	require.Equal(cmd.ErrorCode, cmd2.ErrorCode)
	require.Equal(cmd.Truncated, cmd2.Truncated)
	require.Equal(cmd.LeftOverChunksHint, cmd2.LeftOverChunksHint)
	require.Equal(cmd.Payload, cmd2.Payload)
}

func TestSendT1Command(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	cmd := new(SendT1)
	cmd.Epoch = 123
	cmd.Payload = make([]byte, crypto.Type1MessageSize)

	b := cmd.ToBytes()
	require.Equal(len(b), sendT1Length)

	c, err := FromBytes(b)
	require.NoError(err)
	require.IsType(cmd, c)
	cmd2 := c.(*SendT1)
	require.Equal(cmd.Epoch, cmd2.Epoch)
	require.Equal(cmd.Payload, cmd2.Payload)
}

func TestSendT2Command(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	cmd := new(SendT2)
	cmd.Epoch = 123
	cmd.SrcT1Hash = [sha256.Size]byte{}
	fillRand(require, cmd.SrcT1Hash[:])

	cmd.DstT1Hash = [sha256.Size]byte{}
	fillRand(require, cmd.DstT1Hash[:])
	cmd.Payload = make([]byte, crypto.Type2MessageSize)
	fillRand(require, cmd.Payload[:])

	b := cmd.ToBytes()
	require.Equal(len(b), sendT2Length)

	c, err := FromBytes(b)
	require.NoError(err)
	require.IsType(cmd, c)
	cmd2 := c.(*SendT2)
	require.Equal(cmd.Epoch, cmd2.Epoch)
	require.Equal(cmd.SrcT1Hash, cmd2.SrcT1Hash)
	require.Equal(cmd.DstT1Hash, cmd2.DstT1Hash)
	require.Equal(cmd.Payload, cmd2.Payload)
}

func TestSendT3Command(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	cmd := new(SendT3)
	cmd.Epoch = 123
	cmd.SrcT1Hash = [sha256.Size]byte{}
	fillRand(require, cmd.SrcT1Hash[:])
	cmd.DstT1Hash = [sha256.Size]byte{}
	fillRand(require, cmd.DstT1Hash[:])
	cmd.Payload = make([]byte, crypto.Type2MessageSize)
	fillRand(require, cmd.Payload[:])

	b := cmd.ToBytes()
	require.Equal(len(b), sendT3Length)

	c, err := FromBytes(b)
	require.NoError(err)
	require.IsType(cmd, c)
	cmd2 := c.(*SendT3)
	require.Equal(cmd.Epoch, cmd2.Epoch)
	require.Equal(cmd.SrcT1Hash, cmd2.SrcT1Hash)
	require.Equal(cmd.DstT1Hash, cmd2.DstT1Hash)
	require.Equal(cmd.Payload, cmd2.Payload)
}

func TestMessageResponseCommand(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	cmd := new(MessageResponse)
	cmd.ErrorCode = 123

	b := cmd.ToBytes()
	require.Equal(len(b), messageResponseLength)

	c, err := FromBytes(b)
	require.NoError(err)
	require.IsType(cmd, c)
	cmd2 := c.(*MessageResponse)
	require.Equal(cmd.ErrorCode, cmd2.ErrorCode)
}

func TestMessageResponseCommand2(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	cmd := new(MessageResponse)
	cmd.ErrorCode = 123

	b := cmd.ToBytes()
	require.Equal(len(b), messageResponseLength)

	zeros := [51]byte{}
	b = append(b, zeros[:]...)

	c, err := FromBytes(b)
	require.Error(err)
	require.Equal(nil, c)

	c, err = FromBytes(b[:messageResponseLength])
	require.NoError(err)

	require.IsType(cmd, c)
	cmd2 := c.(*MessageResponse)
	require.Equal(cmd.ErrorCode, cmd2.ErrorCode)
}
