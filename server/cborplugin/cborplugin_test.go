// cborplugin_test.go - tests for backwards compatible cbor plugin system
// Copyright (C) 2021  David Stainton.
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

package cborplugin

import (
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

// OldRequest represents the old plugin Request format (without new fields)
// Used to simulate what old plugins send/receive
type OldRequest struct {
	RequestAt time.Time
	Delay     time.Duration
	ID        uint64
	Payload   []byte
	SURB      []byte
}

// OldResponse represents the old plugin Response format (without new fields)
// Used to simulate what old plugins send/receive
type OldResponse struct {
	RequestAt time.Time
	Delay     time.Duration
	ID        uint64
	Payload   []byte
	SURB      []byte
}

// TestNewServerOldPlugin_RequestCompatibility tests that a new server can send
// requests that old plugins can decode correctly
func TestNewServerOldPlugin_RequestCompatibility(t *testing.T) {
	require := require.New(t)

	// New server creates a regular request
	// Note: CBOR by default truncates time to seconds, so we truncate here too
	newRequest := &Request{
		RequestAt: time.Now().Truncate(time.Second),
		Delay:     100 * time.Millisecond,
		ID:        12345,
		Payload:   []byte("test payload"),
		SURB:      []byte("test surb"),
		// IsParametersRequest is false (default), so omitempty won't include it
	}

	// Serialize with new format
	data, err := cbor.Marshal(newRequest)
	require.NoError(err)

	// Old plugin decodes as OldRequest
	var oldRequest OldRequest
	err = cbor.Unmarshal(data, &oldRequest)
	require.NoError(err)

	// Verify old plugin sees correct data
	require.Equal(newRequest.RequestAt.Unix(), oldRequest.RequestAt.Unix())
	require.Equal(newRequest.Delay, oldRequest.Delay)
	require.Equal(newRequest.ID, oldRequest.ID)
	require.Equal(newRequest.Payload, oldRequest.Payload)
	require.Equal(newRequest.SURB, oldRequest.SURB)
}

// TestNewServerOldPlugin_ResponseCompatibility tests that a new server can decode
// responses from old plugins correctly
func TestNewServerOldPlugin_ResponseCompatibility(t *testing.T) {
	require := require.New(t)

	// Old plugin sends a response
	// Note: CBOR by default truncates time to seconds
	oldResponse := &OldResponse{
		RequestAt: time.Now().Truncate(time.Second),
		Delay:     200 * time.Millisecond,
		ID:        67890,
		Payload:   []byte("response payload"),
		SURB:      []byte("response surb"),
	}

	// Serialize with old format
	data, err := cbor.Marshal(oldResponse)
	require.NoError(err)

	// New server decodes as Response
	var newResponse Response
	err = cbor.Unmarshal(data, &newResponse)
	require.NoError(err)

	// Verify new server sees correct data
	require.Equal(oldResponse.RequestAt.Unix(), newResponse.RequestAt.Unix())
	require.Equal(oldResponse.Delay, newResponse.Delay)
	require.Equal(oldResponse.ID, newResponse.ID)
	require.Equal(oldResponse.Payload, newResponse.Payload)
	require.Equal(oldResponse.SURB, newResponse.SURB)

	// New fields should be zero/false
	require.False(newResponse.IsParametersResponse)
	require.Nil(newResponse.Params)

	// IsRegularResponse should return true
	require.True(newResponse.IsRegularResponse())
}

// TestParametersRequest_OldPluginIgnoresNewFields tests that when a new server
// sends a parameters request, old plugins can still decode it (they just ignore
// the IsParametersRequest field)
func TestParametersRequest_OldPluginIgnoresNewFields(t *testing.T) {
	require := require.New(t)

	// New server sends a parameters request
	paramRequest := NewParametersRequest()

	// Serialize
	data, err := cbor.Marshal(paramRequest)
	require.NoError(err)

	// Old plugin decodes as OldRequest
	var oldRequest OldRequest
	err = cbor.Unmarshal(data, &oldRequest)
	require.NoError(err)

	// Old plugin sees empty request (which it might ignore or error on)
	// The important thing is it doesn't crash
	require.True(oldRequest.RequestAt.IsZero())
	require.Equal(time.Duration(0), oldRequest.Delay)
	require.Equal(uint64(0), oldRequest.ID)
}

// TestParametersResponse_NewPluginToNewServer tests that new plugins can send
// parameter responses that new servers can decode
func TestParametersResponse_NewPluginToNewServer(t *testing.T) {
	require := require.New(t)

	// New plugin creates a parameters response
	params := map[string]interface{}{
		"version": "1.0.0",
		"feature": true,
		"count":   42,
	}
	paramResponse := NewParametersResponse(params)

	// Serialize
	data, err := cbor.Marshal(paramResponse)
	require.NoError(err)

	// New server decodes
	var response Response
	err = cbor.Unmarshal(data, &response)
	require.NoError(err)

	// Verify
	require.True(response.IsParametersResponse)
	require.False(response.IsRegularResponse())
	require.NotNil(response.Params)
	require.Equal("1.0.0", response.Params["version"])
	require.Equal(true, response.Params["feature"])
}

// TestRoundTrip_NewRequest tests that new Request can be serialized and deserialized
func TestRoundTrip_NewRequest(t *testing.T) {
	require := require.New(t)

	// Note: CBOR by default truncates time to seconds
	original := &Request{
		RequestAt:           time.Now().Truncate(time.Second),
		Delay:               500 * time.Millisecond,
		ID:                  99999,
		Payload:             []byte("round trip payload"),
		SURB:                []byte("round trip surb"),
		IsParametersRequest: false,
	}

	data, err := original.Marshal()
	require.NoError(err)

	var decoded Request
	err = decoded.Unmarshal(data)
	require.NoError(err)

	require.Equal(original.RequestAt.Unix(), decoded.RequestAt.Unix())
	require.Equal(original.Delay, decoded.Delay)
	require.Equal(original.ID, decoded.ID)
	require.Equal(original.Payload, decoded.Payload)
	require.Equal(original.SURB, decoded.SURB)
	require.Equal(original.IsParametersRequest, decoded.IsParametersRequest)
}

// TestRoundTrip_NewResponse tests that new Response can be serialized and deserialized
func TestRoundTrip_NewResponse(t *testing.T) {
	require := require.New(t)

	// Note: CBOR by default truncates time to seconds
	original := &Response{
		RequestAt:            time.Now().Truncate(time.Second),
		Delay:                300 * time.Millisecond,
		ID:                   88888,
		Payload:              []byte("response round trip"),
		SURB:                 []byte("response surb"),
		IsParametersResponse: true,
		Params: map[string]interface{}{
			"key1": "value1",
			"key2": 123,
		},
	}

	data, err := original.Marshal()
	require.NoError(err)

	var decoded Response
	err = decoded.Unmarshal(data)
	require.NoError(err)

	require.Equal(original.RequestAt.Unix(), decoded.RequestAt.Unix())
	require.Equal(original.Delay, decoded.Delay)
	require.Equal(original.ID, decoded.ID)
	require.Equal(original.Payload, decoded.Payload)
	require.Equal(original.SURB, decoded.SURB)
	require.Equal(original.IsParametersResponse, decoded.IsParametersResponse)
	require.Equal(original.Params["key1"], decoded.Params["key1"])
}

// TestOmitempty_RegularRequestDoesNotIncludeNewFields verifies that when
// IsParametersRequest is false, it's not included in the CBOR output
func TestOmitempty_RegularRequestDoesNotIncludeNewFields(t *testing.T) {
	require := require.New(t)

	regularRequest := &Request{
		RequestAt: time.Now(),
		Delay:     100 * time.Millisecond,
		ID:        12345,
		Payload:   []byte("test"),
		SURB:      []byte("surb"),
		// IsParametersRequest defaults to false
	}

	data, err := cbor.Marshal(regularRequest)
	require.NoError(err)

	// Decode into a map to check what fields are present
	var rawMap map[string]interface{}
	err = cbor.Unmarshal(data, &rawMap)
	require.NoError(err)

	// IsParametersRequest should NOT be in the map (omitempty)
	_, hasParamField := rawMap["IsParametersRequest"]
	require.False(hasParamField, "IsParametersRequest should not be present when false")
}

// TestOmitempty_RegularResponseDoesNotIncludeNewFields verifies that when
// IsParametersResponse is false and Params is nil, they're not in CBOR output
func TestOmitempty_RegularResponseDoesNotIncludeNewFields(t *testing.T) {
	require := require.New(t)

	regularResponse := &Response{
		RequestAt: time.Now(),
		Delay:     100 * time.Millisecond,
		ID:        12345,
		Payload:   []byte("test"),
		SURB:      []byte("surb"),
		// IsParametersResponse defaults to false, Params defaults to nil
	}

	data, err := cbor.Marshal(regularResponse)
	require.NoError(err)

	// Decode into a map to check what fields are present
	var rawMap map[string]interface{}
	err = cbor.Unmarshal(data, &rawMap)
	require.NoError(err)

	// New fields should NOT be in the map (omitempty)
	_, hasParamRespField := rawMap["IsParametersResponse"]
	require.False(hasParamRespField, "IsParametersResponse should not be present when false")

	_, hasParamsField := rawMap["Params"]
	require.False(hasParamsField, "Params should not be present when nil")
}
