// request_response_test.go - remote spool request and response types tests
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

package common

import (
	"testing"

	"github.com/stretchr/testify/require"

	eddsa "github.com/katzenpost/hpqc/sign/ed25519"
)

func TestCommandSerialization(t *testing.T) {
	require := require.New(t)
	_, pk, err := eddsa.Scheme().GenerateKey()
	signature := eddsa.Scheme().Sign(pk, pk.Public().(*eddsa.PublicKey).Bytes(), nil)
	require.NoError(err)
	cmd, err := CreateSpool(pk)
	require.NoError(err)
	sr := new(SpoolRequest)
	require.NoError(sr.Unmarshal(cmd))
	require.Equal(sr.Command, uint8(CreateSpoolCommand))
	require.NotNil(sr.Signature)
	require.Equal(sr.Signature, signature)
	require.NotNil(sr.PublicKey)
	require.NotNil(sr.MessageID)
}
