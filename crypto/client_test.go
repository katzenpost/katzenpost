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

	require.NoError(nil)
	passphrase := []byte("bridge traffic is busy tonight")
	client, err := NewClient(passphrase)
	require.NoError(err)
	epoch := uint64(1234567)
	sharedRandom := [64]byte{}
	_, err = rand.Reader.Read(sharedRandom[:])
	require.NoError(err)
	payload := []byte("This is the payload.")
	t1, err := client.GenerateType1Message(epoch, sharedRandom[:], payload)
	require.NoError(err)
	t.Logf("t1 %x", t1)
}
