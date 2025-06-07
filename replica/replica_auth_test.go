// SPDX-FileCopyrightText: Copyright (C) 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"crypto/hmac"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/kem/pem"
	kempem "github.com/katzenpost/hpqc/kem/pem"
	kemschemes "github.com/katzenpost/hpqc/kem/schemes"
	nikeschemes "github.com/katzenpost/hpqc/nike/schemes"
	signschemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/pki"
	sConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/replica/common"
	"github.com/katzenpost/katzenpost/replica/config"
)

const (
	testHandshakeTimeout = 500 * time.Millisecond
	testDialTimeout      = 100 * time.Millisecond
)

// setupServer creates a test server with the given configuration
func setupServer(t *testing.T, cfg *config.Config) *Server {
	s, err := New(cfg)
	require.NoError(t, err)
	return s
}

// setupPKIDoc creates a test PKI document with the given replicas and service nodes
func setupPKIDoc(t *testing.T, replicas []*pki.ReplicaDescriptor, serviceNodes []*pki.MixDescriptor) *pki.Document {
	epoch, _, _ := epochtime.Now()
	doc := &pki.Document{
		Epoch:           epoch,
		StorageReplicas: replicas,
		ServiceNodes:    serviceNodes,
	}
	return doc
}

func authenticateCourierConnection(pkiWorker *PKIWorker, creds *wire.PeerCredentials) bool {
	// Check courier authentication
	epoch, _, _ := epochtime.Now()

	// Try current, next, and previous epochs
	doc := pkiWorker.documentForEpoch(epoch)
	if doc == nil {
		doc = pkiWorker.documentForEpoch(epoch + 1)
		if doc == nil {
			doc = pkiWorker.documentForEpoch(epoch - 1)
			if doc == nil {
				return false
			}
		}
	}

	// Check if the public key matches any courier in the PKI document
	for _, desc := range doc.ServiceNodes {
		if desc.Kaetzchen == nil {
			continue
		}
		rawLinkPubKey, err := desc.GetRawCourierLinkKey()
		if err != nil {
			continue
		}
		linkScheme := kemschemes.ByName("Kyber768-X25519") // Use the scheme from this test
		linkPubKey, err := pem.FromPublicPEMString(rawLinkPubKey, linkScheme)
		if err != nil {
			continue
		}
		if creds.PublicKey.Equal(linkPubKey) {
			return true
		}
	}
	return false
}

func authenticateReplicaConnection(pkiWorker *PKIWorker, creds *wire.PeerCredentials) (*pki.ReplicaDescriptor, bool) {
	if len(creds.AdditionalData) != sConstants.NodeIDLength {
		return nil, false
	}
	var nodeID [sConstants.NodeIDLength]byte
	copy(nodeID[:], creds.AdditionalData)
	replicaDesc, isReplica := pkiWorker.replicas.GetReplicaDescriptor(&nodeID)
	if !isReplica {
		return nil, false
	}
	blob, err := creds.PublicKey.MarshalBinary()
	if err != nil {
		panic(err)
	}
	if !hmac.Equal(replicaDesc.LinkKey, blob) {
		return nil, false
	}
	return replicaDesc, true
}

// TestAuthentication tests all authentication paths:
// 1. Courier authentication
// 2. Replica authentication (incoming)
// 3. Replica authentication (outgoing)
func TestAuthentication(t *testing.T) {
	// Setup test environment
	schemes := &TestSchemes{
		PKI:     signschemes.ByName("Ed25519"),
		Link:    kemschemes.ByName("Kyber768-X25519"),
		Replica: nikeschemes.ByName("X25519"),
		Sphinx:  nikeschemes.ByName("X25519"),
	}
	geometry := CreateTestGeometryCustom(schemes, 5000, 5)
	baseDir := CreateTestTempDir(t, "auth_test")

	// Generate keys for test replicas and courier
	replica1Keys := GenerateTestKeys(t, schemes)
	replica2Keys := GenerateTestKeys(t, schemes)
	courierKeys := GenerateTestKeys(t, schemes)
	courierLinkKeyPEM := kempem.ToPublicPEMString(courierKeys.LinkPubKey)

	// Generate envelope keys for replicas
	replicaEpoch, _, _ := common.ReplicaNow()

	// Create replica descriptors with envelope keys
	replica1Desc := &pki.ReplicaDescriptor{
		Name:        "replica1",
		IdentityKey: replica1Keys.IdentityKeyBlob,
		LinkKey:     replica1Keys.LinkKeyBlob,
		Addresses:   map[string][]string{"tcp": {"127.0.0.1:4001"}},
		EnvelopeKeys: map[uint64][]byte{
			replicaEpoch:     make([]byte, schemes.Replica.PublicKeySize()),
			replicaEpoch + 1: make([]byte, schemes.Replica.PublicKeySize()),
		},
	}

	replica2Desc := &pki.ReplicaDescriptor{
		Name:        "replica2",
		IdentityKey: replica2Keys.IdentityKeyBlob,
		LinkKey:     replica2Keys.LinkKeyBlob,
		Addresses:   map[string][]string{"tcp": {"127.0.0.1:4002"}},
		EnvelopeKeys: map[uint64][]byte{
			replicaEpoch:     make([]byte, schemes.Replica.PublicKeySize()),
			replicaEpoch + 1: make([]byte, schemes.Replica.PublicKeySize()),
		},
	}

	// Create courier service node descriptor
	courierDesc := &pki.MixDescriptor{
		Name:        "courier1",
		IdentityKey: courierKeys.IdentityKeyBlob,
		LinkKey:     courierKeys.LinkKeyBlob,
		Addresses:   map[string][]string{"tcp": {"127.0.0.1:4003"}},
		Kaetzchen: map[string]map[string]interface{}{
			"courier": {
				"version":  "0.0.0",
				"endpoint": "+courier",
			},
		},
		KaetzchenAdvertizedData: map[string]map[string]interface{}{
			"courier": {
				"linkPublicKey": courierLinkKeyPEM,
			},
		},
	}

	// Create PKI document
	doc := setupPKIDoc(t, []*pki.ReplicaDescriptor{replica1Desc, replica2Desc}, []*pki.MixDescriptor{courierDesc})

	// Setup replica1 server
	replica1Cfg := CreateTestConfig(t, schemes, geometry, filepath.Join(baseDir, "replica1"), "replica1", []string{"tcp://127.0.0.1:4001"})
	replica1Cfg.HandshakeTimeout = int(testHandshakeTimeout.Milliseconds())
	replica1Cfg.ConnectTimeout = int(testDialTimeout.Milliseconds())
	replica1Cfg.ReauthInterval = int(time.Second.Milliseconds())

	replica1Server := setupServer(t, replica1Cfg)
	replica1Server.identityPublicKey = replica1Keys.IdentityPubKey
	replica1Server.identityPrivateKey = replica1Keys.IdentityPrivKey
	replica1Server.linkKey = replica1Keys.LinkPrivKey

	// Setup replica2 server
	replica2Cfg := CreateTestConfig(t, schemes, geometry, filepath.Join(baseDir, "replica2"), "replica2", []string{"tcp://127.0.0.1:4002"})
	replica2Cfg.HandshakeTimeout = int(testHandshakeTimeout.Milliseconds())
	replica2Cfg.ConnectTimeout = int(testDialTimeout.Milliseconds())
	replica2Cfg.ReauthInterval = int(time.Second.Milliseconds())

	replica2Server := setupServer(t, replica2Cfg)
	replica2Server.identityPublicKey = replica2Keys.IdentityPubKey
	replica2Server.identityPrivateKey = replica2Keys.IdentityPrivKey
	replica2Server.linkKey = replica2Keys.LinkPrivKey

	// Update PKI state with current epoch
	epoch, _, _ := epochtime.Now()
	replica1PKI := replica1Server.PKIWorker
	replica2PKI := replica2Server.PKIWorker

	// Store the document in both PKI workers
	rawDoc, err := doc.MarshalCertificate()
	require.NoError(t, err)
	replica1PKI.StoreDocument(epoch, doc, rawDoc)
	replica2PKI.StoreDocument(epoch, doc, rawDoc)
	replica1PKI.updateReplicas(doc)
	replica2PKI.updateReplicas(doc)

	// Initialize envelope keys for both replicas
	replica1Server.envelopeKeys, err = NewEnvelopeKeys(schemes.Replica, replica1Server.log, replica1Server.cfg.DataDir, replicaEpoch)
	require.NoError(t, err)
	replica2Server.envelopeKeys, err = NewEnvelopeKeys(schemes.Replica, replica2Server.log, replica2Server.cfg.DataDir, replicaEpoch)
	require.NoError(t, err)

	// Test 1: Courier Authentication
	t.Run("CourierAuthentication", func(t *testing.T) {
		// Create courier credentials
		courierCreds := &wire.PeerCredentials{
			AdditionalData: []byte{}, // Couriers have empty additional data
			PublicKey:      courierKeys.LinkPubKey,
		}

		// Test courier authentication from replica1
		isValid := authenticateCourierConnection(replica1PKI, courierCreds)
		require.True(t, isValid)

		// Test with invalid courier link key
		invalidLinkPubKey, _, err := schemes.Link.GenerateKeyPair()
		require.NoError(t, err)
		invalidCourierCreds := &wire.PeerCredentials{
			AdditionalData: []byte{},
			PublicKey:      invalidLinkPubKey,
		}
		isValid = authenticateCourierConnection(replica1PKI, invalidCourierCreds)
		require.False(t, isValid)
	})

	// Test 2: Replica Authentication (Incoming)
	t.Run("ReplicaAuthenticationIncoming", func(t *testing.T) {
		// Create replica credentials
		replica2IdHash := hash.Sum256(replica2Keys.IdentityKeyBlob)
		replica2Creds := &wire.PeerCredentials{
			AdditionalData: replica2IdHash[:],
			PublicKey:      replica2Keys.LinkPubKey,
		}

		// Test replica authentication from replica1
		replicaDesc, isValid := authenticateReplicaConnection(replica1PKI, replica2Creds)
		require.True(t, isValid)
		require.NotNil(t, replicaDesc)
		require.Equal(t, replica2Desc.Name, replicaDesc.Name)
		require.NotEmpty(t, replicaDesc.EnvelopeKeys)
		require.Contains(t, replicaDesc.EnvelopeKeys, replicaEpoch)
		require.Contains(t, replicaDesc.EnvelopeKeys, replicaEpoch+1)

		// Test with invalid identity key
		invalidKeys := GenerateTestKeys(t, schemes)
		invalidIdHash := hash.Sum256(invalidKeys.IdentityKeyBlob)
		invalidCreds := &wire.PeerCredentials{
			AdditionalData: invalidIdHash[:],
			PublicKey:      replica2Keys.LinkPubKey,
		}
		desc, isValid := authenticateReplicaConnection(replica1PKI, invalidCreds)
		require.False(t, isValid)
		require.Nil(t, desc)

		// Test with invalid link key
		invalidLinkKeys := GenerateTestKeys(t, schemes)
		invalidLinkCreds := &wire.PeerCredentials{
			AdditionalData: replica2IdHash[:],
			PublicKey:      invalidLinkKeys.LinkPubKey,
		}
		desc, isValid = authenticateReplicaConnection(replica1PKI, invalidLinkCreds)
		require.False(t, isValid)
		require.Nil(t, desc)
	})

	// Test 3: Replica Authentication (Outgoing)
	t.Run("ReplicaAuthenticationOutgoing", func(t *testing.T) {
		// Create outgoing connection from replica1 to replica2
		outConn := newOutgoingConn(replica1Server.connector, replica2Desc, geometry, schemes.Link)
		require.NotNil(t, outConn)

		// Create replica credentials
		replica2IdHash := hash.Sum256(replica2Keys.IdentityKeyBlob)
		replica2Creds := &wire.PeerCredentials{
			AdditionalData: replica2IdHash[:],
			PublicKey:      replica2Keys.LinkPubKey,
		}

		// Test outgoing authentication
		isValid := outConn.IsPeerValid(replica2Creds)
		require.True(t, isValid)

		// Test with invalid identity key
		invalidKeys := GenerateTestKeys(t, schemes)
		invalidIdHash := hash.Sum256(invalidKeys.IdentityKeyBlob)
		invalidCreds := &wire.PeerCredentials{
			AdditionalData: invalidIdHash[:],
			PublicKey:      replica2Keys.LinkPubKey,
		}
		isValid = outConn.IsPeerValid(invalidCreds)
		require.False(t, isValid)

		// Test with invalid link key
		invalidLinkKeys := GenerateTestKeys(t, schemes)
		invalidLinkCreds := &wire.PeerCredentials{
			AdditionalData: replica2IdHash[:],
			PublicKey:      invalidLinkKeys.LinkPubKey,
		}
		isValid = outConn.IsPeerValid(invalidLinkCreds)
		require.False(t, isValid)
	})
}
