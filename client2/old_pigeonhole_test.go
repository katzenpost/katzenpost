// SPDX-FileCopyrightText: © 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package client2

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/kem"
	kemSchemes "github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/nike"
	nikeSchemes "github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/hpqc/sign"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/client2/constants"
	"github.com/katzenpost/katzenpost/core/epochtime"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/pigeonhole"
	pigeonholeGeo "github.com/katzenpost/katzenpost/pigeonhole/geo"
	replicaCommon "github.com/katzenpost/katzenpost/replica/common"
)

const (
	testPKIScheme = "Ed25519 Sphincs+"
)

func TestCreateChannelWriteRequest(t *testing.T) {
	// Create BACAP stateful writer
	owner, err := bacap.NewWriteCap(rand.Reader)
	require.NoError(t, err)
	statefulWriter, err := bacap.NewStatefulWriter(owner, constants.PIGEONHOLE_CTX)
	require.NoError(t, err)

	payload := []byte("hello world")

	// Create synthetic PKI document with real replica descriptors
	doc := createSyntheticPKIDocument(t)

	// Create geometry with a reasonable MaxPlaintextPayloadLength that can accommodate our payload
	// The CreateChannelWriteRequest function should pad to the geometry's MaxPlaintextPayloadLength + 4
	// MaxPlaintextPayloadLength must be larger than payload (4-byte length prefix is added separately)
	nikeScheme := replicaCommon.NikeScheme
	maxPlaintextPayloadLength := len(payload) + 100 // Add overhead for padding
	geometry := pigeonholeGeo.NewGeometry(maxPlaintextPayloadLength, nikeScheme)

	// Create the CourierEnvelope using the geometry for proper padding
	courierEnvelope, _, err := CreateChannelWriteRequest(
		statefulWriter,
		payload,
		doc,
		geometry)
	require.NoError(t, err)

	// Wrap CourierEnvelope in CourierQuery to get actual size
	courierQuery := &pigeonhole.CourierQuery{
		QueryType: 0, // 0 = envelope
		Envelope:  courierEnvelope,
	}
	query := courierQuery.Bytes()
	actualSize := len(query)

	// Test size of "query" against geometry prediction
	expectedSize := geometry.CourierQueryWriteLength

	t.Logf("Actual CourierQuery size: %d bytes", actualSize)
	t.Logf("Expected CourierQuery size: %d bytes", expectedSize)
	t.Logf("Difference: %d bytes", expectedSize-actualSize)
	t.Logf("Geometry: %s", geometry.String())

	// The actual size should match the geometry prediction
	require.Equal(t, expectedSize, actualSize, "CourierQuery size should match geometry prediction")
}

func TestCreateChannelWriteRequestPayloadTooLarge(t *testing.T) {
	// Create BACAP stateful writer
	owner, err := bacap.NewWriteCap(rand.Reader)
	require.NoError(t, err)
	statefulWriter, err := bacap.NewStatefulWriter(owner, constants.PIGEONHOLE_CTX)
	require.NoError(t, err)

	// Create a payload that's too large
	smallMaxPlaintextPayloadLength := 10                            // Very small MaxPlaintextPayloadLength
	largePayload := make([]byte, smallMaxPlaintextPayloadLength+10) // This will be too large even with the 4-byte length prefix

	// Create synthetic PKI document
	doc := createSyntheticPKIDocument(t)

	// Create geometry with small MaxPlaintextPayloadLength
	nikeScheme := replicaCommon.NikeScheme
	geometry := pigeonholeGeo.NewGeometry(smallMaxPlaintextPayloadLength, nikeScheme)

	// This should fail with payload too large error
	_, _, err = CreateChannelWriteRequest(
		statefulWriter,
		largePayload,
		doc,
		geometry)

	require.Error(t, err)
	require.Contains(t, err.Error(), "payload too large")
	require.Contains(t, err.Error(), "exceeds MaxPlaintextPayloadLength")
	t.Logf("Expected error: %s", err.Error())
}

// createSyntheticPKIDocument creates a synthetic PKI document with real replica descriptors
// for testing purposes, inspired by the integration tests
func createSyntheticPKIDocument(t *testing.T) *cpki.Document {
	// Create schemes like integration tests
	pkiScheme := signSchemes.ByName(testPKIScheme)
	if pkiScheme == nil {
		// Fallback to Ed25519 if the hybrid scheme is not available
		pkiScheme = signSchemes.ByName("Ed25519")
		require.NotNil(t, pkiScheme, "Ed25519 signature scheme should be available")
	}

	linkScheme := kemSchemes.ByName("Xwing")
	if linkScheme == nil {
		// Fallback to X25519 if Xwing is not available
		linkScheme = kemSchemes.ByName("X25519")
		require.NotNil(t, linkScheme, "X25519 KEM scheme should be available")
	}

	nikeScheme := replicaCommon.NikeScheme
	require.NotNil(t, nikeScheme, "NIKE scheme should be available")

	// Create 5 replica descriptors to ensure we have enough for intermediate routing
	// (need at least 4: 2 for shards + 2 for intermediate replicas)
	numReplicas := 5
	replicaDescriptors := make([]*cpki.ReplicaDescriptor, numReplicas)

	for i := 0; i < numReplicas; i++ {
		replicaDescriptors[i] = createReplicaDescriptor(t, i, pkiScheme, linkScheme, nikeScheme)
	}

	// Create a basic sphinx geometry for the document
	sphinxNikeScheme := nikeSchemes.ByName("X25519")
	require.NotNil(t, sphinxNikeScheme, "X25519 NIKE scheme should be available for sphinx geometry")
	sphinxGeo := geo.GeometryFromUserForwardPayloadLength(sphinxNikeScheme, 5000, true, 5)

	// Get current epoch
	currentEpoch, _, _ := epochtime.Now()

	return &cpki.Document{
		Epoch:              currentEpoch,
		SendRatePerMinute:  100,
		LambdaP:            0.1,
		LambdaL:            0.1,
		LambdaD:            0.1,
		LambdaM:            0.1,
		StorageReplicas:    replicaDescriptors,
		Topology:           make([][]*cpki.MixDescriptor, 0),
		GatewayNodes:       make([]*cpki.MixDescriptor, 0),
		ServiceNodes:       make([]*cpki.MixDescriptor, 0),
		SharedRandomValue:  make([]byte, 32),
		SphinxGeometryHash: sphinxGeo.Hash(),
	}
}

// createReplicaDescriptor creates a single replica descriptor for testing
func createReplicaDescriptor(t *testing.T, replicaID int, pkiScheme sign.Scheme, linkScheme kem.Scheme, nikeScheme nike.Scheme) *cpki.ReplicaDescriptor {
	// Generate identity key pair
	identityPubKey, _, err := pkiScheme.GenerateKey()
	require.NoError(t, err)
	identityPubKeyBytes, err := identityPubKey.MarshalBinary()
	require.NoError(t, err)

	// Generate link key pair
	linkPubKey, _, err := linkScheme.GenerateKeyPair()
	require.NoError(t, err)
	linkPubKeyBytes, err := linkPubKey.MarshalBinary()
	require.NoError(t, err)

	// Generate replica NIKE key pair
	replicaPubKey, _, err := nikeScheme.GenerateKeyPair()
	require.NoError(t, err)
	replicaPubKeyBytes, err := replicaPubKey.MarshalBinary()
	require.NoError(t, err)

	// Get current replica epoch
	replicaEpoch, _, _ := replicaCommon.ReplicaNow()

	return &cpki.ReplicaDescriptor{
		Name:        fmt.Sprintf("replica%d", replicaID),
		IdentityKey: identityPubKeyBytes,
		LinkKey:     linkPubKeyBytes,
		Addresses: map[string][]string{
			"tcp": {fmt.Sprintf("tcp://127.0.0.1:%d", 19000+replicaID)},
		},
		EnvelopeKeys: map[uint64][]byte{
			replicaEpoch: replicaPubKeyBytes,
		},
	}
}
