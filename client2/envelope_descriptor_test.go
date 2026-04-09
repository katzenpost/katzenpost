// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client2

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"

	"github.com/katzenpost/katzenpost/client2/constants"
	cpki "github.com/katzenpost/katzenpost/core/pki"
)

func TestEnvelopeDescriptorRoundTrip(t *testing.T) {
	desc := &EnvelopeDescriptor{
		Epoch:       42,
		ReplicaNums: [2]uint8{3, 7},
		EnvelopeKey: []byte("test-key-data-here"),
	}

	blob, err := desc.Bytes()
	require.NoError(t, err)
	require.NotEmpty(t, blob)

	desc2, err := EnvelopeDescriptorFromBytes(blob)
	require.NoError(t, err)
	require.Equal(t, desc.Epoch, desc2.Epoch)
	require.Equal(t, desc.ReplicaNums, desc2.ReplicaNums)
	require.Equal(t, desc.EnvelopeKey, desc2.EnvelopeKey)
}

func TestEnvelopeDescriptorFromBytesInvalid(t *testing.T) {
	_, err := EnvelopeDescriptorFromBytes([]byte("not cbor"))
	require.Error(t, err)

	_, err = EnvelopeDescriptorFromBytes(nil)
	require.Error(t, err)

	_, err = EnvelopeDescriptorFromBytes([]byte{})
	require.Error(t, err)
}

func TestEnvelopeDescriptorZeroValues(t *testing.T) {
	desc := &EnvelopeDescriptor{}

	blob, err := desc.Bytes()
	require.NoError(t, err)

	desc2, err := EnvelopeDescriptorFromBytes(blob)
	require.NoError(t, err)
	require.Equal(t, uint64(0), desc2.Epoch)
	require.Equal(t, [2]uint8{0, 0}, desc2.ReplicaNums)
	require.Nil(t, desc2.EnvelopeKey)
}

func TestEnvelopeDescriptorLargeKey(t *testing.T) {
	largeKey := make([]byte, 4096)
	for i := range largeKey {
		largeKey[i] = byte(i % 256)
	}
	desc := &EnvelopeDescriptor{
		Epoch:       ^uint64(0), // max uint64
		ReplicaNums: [2]uint8{255, 254},
		EnvelopeKey: largeKey,
	}

	blob, err := desc.Bytes()
	require.NoError(t, err)

	desc2, err := EnvelopeDescriptorFromBytes(blob)
	require.NoError(t, err)
	require.Equal(t, desc.Epoch, desc2.Epoch)
	require.Equal(t, desc.ReplicaNums, desc2.ReplicaNums)
	require.Equal(t, desc.EnvelopeKey, desc2.EnvelopeKey)
}

func TestGetRandomCourier(t *testing.T) {
	t.Run("no courier services", func(t *testing.T) {
		doc := &cpki.Document{
			ServiceNodes: []*cpki.MixDescriptor{
				{
					Name:        "service1",
					IdentityKey: []byte("identity-key-for-testing-123456!"),
					Kaetzchen: map[string]map[string]interface{}{
						"echo": {"endpoint": "echo"},
					},
				},
			},
		}
		_, _, err := GetRandomCourier(doc)
		require.Error(t, err)
		require.Contains(t, err.Error(), "no courier services")
	})

	t.Run("single courier", func(t *testing.T) {
		identityKey := []byte("courier-identity-key-testing-12!")
		expectedHash := hash.Sum256(identityKey)
		doc := &cpki.Document{
			ServiceNodes: []*cpki.MixDescriptor{
				{
					Name:        "courier1",
					IdentityKey: identityKey,
					Kaetzchen: map[string]map[string]interface{}{
						constants.CourierServiceName: {"endpoint": "courier"},
					},
				},
			},
		}
		idHash, queueID, err := GetRandomCourier(doc)
		require.NoError(t, err)
		require.Equal(t, expectedHash, *idHash)
		require.Equal(t, []byte("courier"), queueID)
	})

	t.Run("multiple couriers", func(t *testing.T) {
		doc := &cpki.Document{
			ServiceNodes: []*cpki.MixDescriptor{
				{
					Name:        "courier1",
					IdentityKey: []byte("courier-identity-key-one-123456!"),
					Kaetzchen: map[string]map[string]interface{}{
						constants.CourierServiceName: {"endpoint": "courier1"},
					},
				},
				{
					Name:        "courier2",
					IdentityKey: []byte("courier-identity-key-two-123456!"),
					Kaetzchen: map[string]map[string]interface{}{
						constants.CourierServiceName: {"endpoint": "courier2"},
					},
				},
			},
		}
		// Just verify it returns a valid result (randomized)
		idHash, queueID, err := GetRandomCourier(doc)
		require.NoError(t, err)
		require.NotNil(t, idHash)
		require.NotEmpty(t, queueID)
	})
}
