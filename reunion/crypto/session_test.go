// client_test.go - Cryptographic client tests.
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

package crypto

import (
	"testing"

	"github.com/katzenpost/hpqc/rand"
	"github.com/stretchr/testify/require"
)

func TestClientBasics(t *testing.T) {
	require := require.New(t)

	epoch := uint64(1234567)
	sharedRandom := [64]byte{}
	_, err := rand.Reader.Read(sharedRandom[:])
	require.NoError(err)
	payload1 := []byte("This is the payload1")
	payload2 := []byte("This is the payload2")

	sharedEpochKey1 := [SharedEpochKeySize]byte{}
	_, err = rand.Reader.Read(sharedEpochKey1[:])
	require.NoError(err)
	sharedEpochKey2 := [SharedEpochKeySize]byte{}
	copy(sharedEpochKey2[:], sharedEpochKey1[:])

	client1, err := NewSessionFromKey(&sharedEpochKey1, sharedRandom[:], epoch)
	require.NoError(err)
	defer client1.Destroy()

	client2, err := NewSessionFromKey(&sharedEpochKey2, sharedRandom[:], epoch)
	require.NoError(err)
	defer client2.Destroy()

	client1T1, err := client1.GenerateType1Message(payload1)
	require.NoError(err)

	client2T1, err := client2.GenerateType1Message(payload2)
	require.NoError(err)

	client1T1Alpha, client1T1Beta, client1T1Gamma, err := DecodeT1Message(client1T1)
	require.NoError(err)
	client2T2, client1B1, err := client2.ProcessType1MessageAlpha(client1T1Alpha)
	require.NoError(err)

	client2T1Alpha, client2T1Beta, client2T1Gamma, err := DecodeT1Message(client2T1)
	require.NoError(err)
	client1T2, client2B1, err := client1.ProcessType1MessageAlpha(client2T1Alpha)
	require.NoError(err)

	client1CandidateKey, err := client1.GetCandidateKey(client2T2, client2B1)
	require.NoError(err)

	client2CandidateKey, err := client2.GetCandidateKey(client1T2, client1B1)
	require.NoError(err)

	require.Equal(client2CandidateKey, client1.sessionKey1[:])
	require.Equal(client1CandidateKey, client2.sessionKey1[:])

	client1B2, err := DecryptT1Beta(client1CandidateKey, client2T1Beta)
	require.NoError(err)
	require.Equal(client2.keypair2.Public().Bytes()[:], client1B2.Bytes()[:])

	client2B2, err := DecryptT1Beta(client2CandidateKey, client1T1Beta)
	require.NoError(err)
	require.Equal(client1.keypair2.Public().Bytes()[:], client2B2.Bytes()[:])

	client1T3, err := client1.ComposeType3Message(client1B2)
	require.NoError(err)

	client2T3, err := client2.ComposeType3Message(client2B2)
	require.NoError(err)

	plaintext1, err := client1.ProcessType3Message(client2T3, client2T1Gamma, client1B2)
	require.NoError(err)

	plaintext2, err := client2.ProcessType3Message(client1T3, client1T1Gamma, client2B2)
	require.NoError(err)

	require.Equal(payload1, plaintext2)
	require.Equal(payload2, plaintext1)
}

func TestClientSerialization(t *testing.T) {
	require := require.New(t)

	epoch := uint64(1234567)
	sharedRandom := [64]byte{}
	_, err := rand.Reader.Read(sharedRandom[:])
	require.NoError(err)

	sharedEpochKey := [SharedEpochKeySize]byte{}
	_, err = rand.Reader.Read(sharedEpochKey[:])
	require.NoError(err)

	client, err := NewSessionFromKey(&sharedEpochKey, sharedRandom[:], epoch)
	require.NoError(err)
	defer client.Destroy()

	serialized, err := client.MarshalBinary()
	require.NoError(err)

	blankEpochKey := [SharedEpochKeySize]byte{}
	client2, err := NewSessionFromKey(&blankEpochKey, sharedRandom[:], epoch)
	require.NoError(err)
	defer client2.Destroy()

	err = client2.UnmarshalBinary(serialized)
	require.NoError(err)

	serialized2, err := client2.MarshalBinary()
	require.NoError(err)

	client3, err := NewSessionFromKey(&blankEpochKey, sharedRandom[:], epoch)
	require.NoError(err)
	defer client3.Destroy()

	err = client3.UnmarshalBinary(serialized2)
	require.NoError(err)

	serialized3, err := client3.MarshalBinary()
	require.NoError(err)

	require.Equal(serialized2, serialized3)
}
