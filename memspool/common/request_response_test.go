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

	"github.com/stretchr/testify/assert"
)

func TestSerializationPaddingSymmetry(t *testing.T) {
	assert := assert.New(t)
	sig := [64]byte{}
	spoolID := [SpoolIDSize]byte{}
	publicKey := [32]byte{}
	request := SpoolRequest{
		Command:   1,
		SpoolID:   spoolID,
		Signature: sig[:],
		PublicKey: publicKey[:],
		MessageID: 0,
		Message:   []byte("hello123"),
	}
	requestRaw, err := request.Marshal()
	assert.NoError(err)

	response := SpoolResponse{
		SpoolID: spoolID,
		Message: []byte("hello123"),
		Status:  "OK",
	}
	responseRaw, err := response.Marshal()
	assert.NoError(err)
	assert.Equal(len(requestRaw), len(responseRaw))

	t.Logf("request overhead is %d", (len(requestRaw) - len(request.Message)))
	t.Logf("response overhead is %d", (len(responseRaw) - len(response.Message)))
}
