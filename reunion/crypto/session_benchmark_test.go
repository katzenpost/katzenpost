// client_benchmark_test.go - Reunion core crypto client benchmarks.
// Copyright (C) 2019 David Stainton.
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

func BenchmarkBasicTwoClientExchange(b *testing.B) {
	require := require.New(b)

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

	client2, err := NewSessionFromKey(&sharedEpochKey2, sharedRandom[:], epoch)
	require.NoError(err)

	for n := 0; n < b.N; n++ {
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

		require.Equal(client2CandidateKey, client1.sessionKey1)
		require.Equal(client1CandidateKey, client2.sessionKey1)

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
}

type testData struct {
	epoch        uint64
	sharedRandom []byte
	sessions     []*Session
	t1s          [][]byte
	phase2       []*phase2State
}

type phase2State struct {
	t2                 []byte
	beta, gamma, beta2 []byte
}

func createMultiClientBenchmarkData(b *testing.B, n int) *testData {
	require := require.New(b)

	payload1 := []byte("This is the payload1")
	epoch := uint64(1234567)
	sharedEpochKey := [SharedEpochKeySize]byte{}
	_, err := rand.Reader.Read(sharedEpochKey[:])
	require.NoError(err)
	sharedEpochKey2 := [SharedEpochKeySize]byte{}
	_, err = rand.Reader.Read(sharedEpochKey2[:])
	require.NoError(err)
	sharedRandom := [64]byte{}
	_, err = rand.Reader.Read(sharedRandom[:])
	require.NoError(err)

	tests := testData{
		epoch:        epoch,
		sharedRandom: sharedRandom[:],
		sessions:     make([]*Session, n),
		t1s:          make([][]byte, n),
		phase2:       make([]*phase2State, 0),
	}
	k := 2

	// phase 1
	for i := 0; i < k; i++ {
		client, err := NewSessionFromKey(&sharedEpochKey, sharedRandom[:], epoch)
		require.NoError(err)

		tests.sessions[i] = client

		t1, err := client.GenerateType1Message(payload1)
		require.NoError(err)

		tests.t1s[i] = t1
	}

	for i := k; i < n; i++ {
		sharedRandom2 := [64]byte{}
		_, err := rand.Reader.Read(sharedRandom2[:])
		require.NoError(err)

		client, err := NewSessionFromKey(&sharedEpochKey2, sharedRandom[:], epoch)
		require.NoError(err)

		tests.sessions[i] = client

		t1, err := client.GenerateType1Message(payload1)
		require.NoError(err)

		tests.t1s[i] = t1
	}

	// phase 2
	for i := 1; i < len(tests.sessions); i++ {
		alpha, beta, gamma, err := DecodeT1Message(tests.t1s[0])
		require.NoError(err)
		t2, beta2, err := tests.sessions[i].ProcessType1MessageAlpha(alpha)
		require.NoError(err)

		tests.phase2 = append(tests.phase2, &phase2State{
			t2:    t2,
			beta:  beta,
			gamma: gamma,
			beta2: beta2.Bytes()[:],
		})
	}

	// phase 3
	for i := 0; i < len(tests.phase2); i++ {
		state := tests.phase2[i]
		beta2PubKey, err := NewPublicKey(state.beta2)
		require.NoError(err)
		candidateKey, err := tests.sessions[0].GetCandidateKey(state.t2, beta2PubKey)
		require.NoError(err)
		_, err = DecryptT1Beta(candidateKey, state.beta)
		require.NoError(err)
	}
	return &tests
}

func BenchmarkPhases(b *testing.B) {
	require := require.New(b)

	tests := createMultiClientBenchmarkData(b, 1000)
	runPhase2Tests := func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			for i := 1; i < len(tests.t1s); i++ {
				client1T1Alpha, _, _, err := DecodeT1Message(tests.t1s[i])
				require.NoError(err)
				_, _, err = tests.sessions[0].ProcessType1MessageAlpha(client1T1Alpha)
				require.NoError(err)
			}
		}
	}
	b.Run("phase2", runPhase2Tests)
	runPhase3Tests := func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			for i := 1; i < len(tests.phase2); i++ {
				state := tests.phase2[i]
				beta2PubKey, err := NewPublicKey(state.beta2)
				require.NoError(err)
				candidateKey, err := tests.sessions[0].GetCandidateKey(state.t2, beta2PubKey)
				require.NoError(err)
				_, err = DecryptT1Beta(candidateKey, state.beta)
				require.NoError(err)
				_, err = tests.sessions[0].ComposeType3Message(beta2PubKey)
				require.NoError(err)
			}
		}
	}
	b.Run("phase3", runPhase3Tests)
}
