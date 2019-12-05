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

	"github.com/katzenpost/core/crypto/rand"
	"github.com/stretchr/testify/require"
)

func TestClientBasics(t *testing.T) {
	require := require.New(t)

	epoch := uint64(1234567)
	sharedRandom := [64]byte{}
	passphrase := []byte("bridge traffic is busy tonight")

	client1, err := NewClient(passphrase, sharedRandom[:], epoch)
	require.NoError(err)
	_, err = rand.Reader.Read(sharedRandom[:])
	require.NoError(err)
	payload := []byte("This is the payload.")

	client1T1, err := client1.GenerateType1Message(epoch, sharedRandom[:], payload)
	require.NoError(err)

	client2, err := NewClient(passphrase, sharedRandom[:], epoch)
	require.NoError(err)

	client2T1, err := client2.GenerateType1Message(epoch, sharedRandom[:], payload)
	require.NoError(err)
	t.Logf("client2 t1 %x", client2T1)

	client2T2, client1B1, err := client2.ProcessType1MessageAlpha(client1T1, sharedRandom[:], epoch)
	require.NoError(err)

	client1CandidateKey, err := client1.GetCandidateKey(client2T2, client1B1, epoch, sharedRandom[:])
	require.NoError(err)

	t.Logf("client1CandidateKey %x", client1CandidateKey)
}
