// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"fmt"
	"os"
	"testing"

	replicaCommon "github.com/katzenpost/katzenpost/replica/common"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/kem"
	kemschemes "github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/nike"
	nikeschemes "github.com/katzenpost/hpqc/nike/schemes"
	ecdh "github.com/katzenpost/hpqc/nike/x25519"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/hpqc/sign"
	signschemes "github.com/katzenpost/hpqc/sign/schemes"

	authconfig "github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/wire/commands"
	"github.com/katzenpost/katzenpost/replica/config"
)

const (
	// Test constants used across multiple test files
	testPKIScheme         = "Ed25519 Sphincs+"
	testReplicaNameFormat = "replica%d"
	testDefaultNrHops     = 5
	testDefaultPayload    = 5000
)

// TestSchemes holds the cryptographic schemes used in tests
type TestSchemes struct {
	PKI     sign.Scheme
	Link    kem.Scheme
	Replica nike.Scheme
	Sphinx  nike.Scheme
}

// NewTestSchemes creates standard test schemes
func NewTestSchemes() *TestSchemes {
	return &TestSchemes{
		PKI:     signschemes.ByName("ed25519"),
		Link:    kemschemes.ByName("x25519"),
		Replica: nikeschemes.ByName("x25519"),
		Sphinx:  nikeschemes.ByName("x25519"),
	}
}

// NewTestSchemesAdvanced creates advanced test schemes
func NewTestSchemesAdvanced() *TestSchemes {
	return &TestSchemes{
		PKI:     signschemes.ByName(testPKIScheme),
		Link:    kemschemes.ByName("Xwing"),
		Replica: nikeschemes.ByName("x25519"),
		Sphinx:  nikeschemes.ByName("x25519"),
	}
}

// CreateTestGeometry creates a standard test geometry
func CreateTestGeometry(schemes *TestSchemes) *geo.Geometry {
	return geo.GeometryFromUserForwardPayloadLength(schemes.Sphinx, testDefaultPayload, true, testDefaultNrHops)
}

// CreateTestGeometryCustom creates a custom test geometry
func CreateTestGeometryCustom(schemes *TestSchemes, payloadSize, nrHops int) *geo.Geometry {
	return geo.GeometryFromUserForwardPayloadLength(schemes.Sphinx, payloadSize, true, nrHops)
}

// CreateTestTempDir creates a temporary directory for tests
func CreateTestTempDir(t *testing.T, prefix string) string {
	dname, err := os.MkdirTemp("", fmt.Sprintf("%s_%d", prefix, os.Getpid()))
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(dname) })
	return dname
}

// GenerateTestKeys generates a complete set of test keys
type TestKeys struct {
	IdentityPubKey  sign.PublicKey
	IdentityPrivKey sign.PrivateKey
	IdentityKeyBlob []byte
	LinkPubKey      kem.PublicKey
	LinkPrivKey     kem.PrivateKey
	LinkKeyBlob     []byte
	ReplicaPubKey   nike.PublicKey
	ReplicaPrivKey  nike.PrivateKey
	ReplicaKeyBlob  []byte
}

// GenerateTestKeys creates a complete set of test keys
func GenerateTestKeys(t *testing.T, schemes *TestSchemes) *TestKeys {
	// Generate identity key
	identityPubKey, identityPrivKey, err := schemes.PKI.GenerateKey()
	require.NoError(t, err)
	identityKeyBlob, err := identityPubKey.MarshalBinary()
	require.NoError(t, err)

	// Generate link key
	linkPubKey, linkPrivKey, err := schemes.Link.GenerateKeyPair()
	require.NoError(t, err)
	linkKeyBlob, err := linkPubKey.MarshalBinary()
	require.NoError(t, err)

	// Generate replica key
	replicaPubKey, replicaPrivKey, err := schemes.Replica.GenerateKeyPair()
	require.NoError(t, err)
	replicaKeyBlob, err := replicaPubKey.MarshalBinary()
	require.NoError(t, err)

	return &TestKeys{
		IdentityPubKey:  identityPubKey,
		IdentityPrivKey: identityPrivKey,
		IdentityKeyBlob: identityKeyBlob,
		LinkPubKey:      linkPubKey,
		LinkPrivKey:     linkPrivKey,
		LinkKeyBlob:     linkKeyBlob,
		ReplicaPubKey:   replicaPubKey,
		ReplicaPrivKey:  replicaPrivKey,
		ReplicaKeyBlob:  replicaKeyBlob,
	}
}

// CreateTestConfig creates a standard test configuration
func CreateTestConfig(t *testing.T, schemes *TestSchemes, geometry *geo.Geometry, dataDir, identifier string, addresses []string) *config.Config {
	// Generate authority keys for PKI config
	authKeys := GenerateTestKeys(t, schemes)

	return &config.Config{
		PKI: &config.PKI{
			Voting: &config.Voting{
				Authorities: []*authconfig.Authority{
					{
						Identifier:         "dirauth1",
						IdentityPublicKey:  authKeys.IdentityPubKey,
						PKISignatureScheme: schemes.PKI.Name(),
						LinkPublicKey:      authKeys.LinkPubKey,
						WireKEMScheme:      schemes.Link.Name(),
						Addresses:          []string{"tcp://127.0.0.1:1234"},
					},
				},
			},
		},
		Logging: &config.Logging{
			Disable: false,
			File:    "",
			Level:   "DEBUG",
		},
		DataDir:            dataDir,
		Identifier:         identifier,
		WireKEMScheme:      schemes.Link.Name(),
		PKISignatureScheme: schemes.PKI.Name(),
		ReplicaNIKEScheme:  schemes.Replica.Name(),
		SphinxGeometry:     geometry,
		Addresses:          addresses,
	}
}

// CreateTestServer creates a test server with PKI worker
func CreateTestServer(t *testing.T, cfg *config.Config, keys *TestKeys, logBackend *log.Backend) *Server {
	pkiWorker := &PKIWorker{
		replicas:   replicaCommon.NewReplicaMap(),
		WorkerBase: pki.NewWorkerBase(nil, nil),
	}

	s := &Server{
		identityPublicKey:  keys.IdentityPubKey,
		identityPrivateKey: keys.IdentityPrivKey,
		linkKey:            keys.LinkPrivKey,
		cfg:                cfg,
		PKIWorker:          pkiWorker,
	}

	if logBackend != nil {
		s.logBackend = logBackend
	}

	pkiWorker.server = s
	s.connector = newMockConnector(s)

	return s
}

// GenerateTestReplica creates a test replica descriptor
func GenerateTestReplica(t *testing.T, schemes *TestSchemes, index int) *pki.ReplicaDescriptor {
	keys := GenerateTestKeys(t, schemes)

	// Create replica descriptor
	replica := &pki.ReplicaDescriptor{
		Name:        fmt.Sprintf(testReplicaNameFormat, index),
		ReplicaID:   uint8(index),
		IdentityKey: keys.IdentityKeyBlob,
		LinkKey:     keys.LinkKeyBlob,
		Addresses:   map[string][]string{"tcp": {fmt.Sprintf("tcp://127.0.0.1:%d", 19000+index)}},
	}

	// Add envelope keys (using current epoch)
	epoch, _, _ := epochtime.Now()
	replica.EnvelopeKeys = make(map[uint64][]byte)
	replica.EnvelopeKeys[epoch] = keys.ReplicaKeyBlob

	return replica
}

// CreateTestPKIDocument creates a test PKI document
func CreateTestPKIDocument(t *testing.T, replicas []*pki.ReplicaDescriptor, serviceNodes []*pki.MixDescriptor) *pki.Document {
	epoch, _, _ := epochtime.Now()

	// Build ConfiguredReplicaIDs from the replica descriptors
	configuredReplicaIDs := make([]uint8, len(replicas))
	for i, desc := range replicas {
		configuredReplicaIDs[i] = desc.ReplicaID
	}

	// Build ConfiguredReplicaIdentityKeys from the replica descriptors
	configuredReplicaKeys := make([][]byte, len(replicas))
	for i, desc := range replicas {
		configuredReplicaKeys[i] = make([]byte, len(desc.IdentityKey))
		copy(configuredReplicaKeys[i], desc.IdentityKey)
	}

	return &pki.Document{
		Epoch:                         epoch,
		StorageReplicas:               replicas,
		ConfiguredReplicaIDs:          configuredReplicaIDs,
		ConfiguredReplicaIdentityKeys: configuredReplicaKeys,
		ServiceNodes:                  serviceNodes,
	}
}

// StoreTestDocument stores a PKI document in a PKI worker
func StoreTestDocument(t *testing.T, pkiWorker *PKIWorker, doc *pki.Document) {
	rawDoc, err := doc.MarshalCertificate()
	require.NoError(t, err)
	pkiWorker.StoreDocument(doc.Epoch, doc, rawDoc)
}

// CreateTestGeometryECDH creates a test geometry using ECDH
func CreateTestGeometryECDH(forwardPayloadLength, nrHops int) *geo.Geometry {
	nike := ecdh.Scheme(rand.Reader)
	return geo.GeometryFromUserForwardPayloadLength(nike, forwardPayloadLength, true, nrHops)
}

// mockConnector is a mock implementation of GenericConnector for testing
type mockConnector struct {
	server *Server
}

// newMockConnector creates a new mock connector
func newMockConnector(s *Server) *mockConnector {
	return &mockConnector{
		server: s,
	}
}

func (m *mockConnector) Server() *Server {
	return m.server
}

func (m *mockConnector) CloseAllCh() chan interface{} {
	return nil
}

func (m *mockConnector) OnClosedConn(conn *outgoingConn) {
	// Mock implementation: no-op for testing purposes
}

func (m *mockConnector) Halt() {
	// Mock implementation: no-op for testing purposes
}

func (m *mockConnector) ForceUpdate() {
	// Mock implementation: no-op for testing purposes
}

func (m *mockConnector) DispatchReplication(cmd *commands.ReplicaWrite) {
	// Mock implementation: no-op for testing purposes
}

func (m *mockConnector) DispatchCommand(cmd commands.Command, idHash *[32]byte) {
	// Mock implementation: no-op for testing purposes
}

func (m *mockConnector) QueueForRetry(cmd commands.Command, idHash [32]byte) {
	// Mock implementation: no-op for testing purposes
}
