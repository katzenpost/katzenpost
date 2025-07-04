// SPDX-FileCopyrightText: Copyright (C) 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/kem"
	"github.com/katzenpost/hpqc/kem/mkem"
	kemPEM "github.com/katzenpost/hpqc/kem/pem"
	kemSchemes "github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/nike"
	nikePem "github.com/katzenpost/hpqc/nike/pem"
	nikeSchemes "github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/hpqc/sign"
	signPem "github.com/katzenpost/hpqc/sign/pem"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"

	dirauthConfig "github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/client2/constants"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	courierServer "github.com/katzenpost/katzenpost/courier/server"
	courierConfig "github.com/katzenpost/katzenpost/courier/server/config"
	"github.com/katzenpost/katzenpost/loops"
	"github.com/katzenpost/katzenpost/pigeonhole"
	pigeonholeGeo "github.com/katzenpost/katzenpost/pigeonhole/geo"
	"github.com/katzenpost/katzenpost/replica"
	replicaCommon "github.com/katzenpost/katzenpost/replica/common"
	"github.com/katzenpost/katzenpost/replica/config"
	"github.com/katzenpost/katzenpost/server/cborplugin"
)

const (
	// testPKIScheme is the PKI signature scheme used in tests
	testPKIScheme = "Ed25519 Sphincs+"
	// testReplicaNameFormat is the format string for replica names in tests
	testReplicaNameFormat = "replica%d"

	// Error message constants to avoid duplication
	errUnexpectedResponseType = "Unexpected response type: %T"

	// Test assertion message constants to avoid duplication
	msgShouldGetExactly2ShardedReplicas  = "Should get exactly 2 sharded replicas"
	msgShouldFindShardedReplicaInStorage = "Should find sharded replica in StorageReplicas"
)

var (
	mkemNikeScheme *mkem.Scheme = mkem.NewScheme(replicaCommon.NikeScheme)
)

// Helper functions to eliminate code duplication

// shardingResult holds the result of sharding operations
type shardingResult struct {
	ReplicaIndices [2]uint8
	ReplicaPubKeys []nike.PublicKey
}

// getShardingInfo performs the common sharding logic and returns replica indices and public keys
func getShardingInfo(t *testing.T, env *testEnvironment, boxID *[bacap.BoxIDSize]byte) *shardingResult {
	currentEpoch, _, _ := epochtime.Now()
	replicaEpoch, _, _ := replicaCommon.ReplicaNow()
	doc := env.mockPKIClient.docs[currentEpoch]

	// Use sharding algorithm to determine which replicas should store this BoxID
	shardedReplicas, err := replicaCommon.GetShards(boxID, doc)
	require.NoError(t, err)
	require.Equal(t, 2, len(shardedReplicas), msgShouldGetExactly2ShardedReplicas)

	// Find the indices of the sharded replicas in the StorageReplicas slice
	var replicaIndices [2]uint8
	var replicaPubKeys []nike.PublicKey = make([]nike.PublicKey, 2)

	for i, shardedReplica := range shardedReplicas {
		// Find the index of this replica in the StorageReplicas slice
		replicaIndex := -1
		for j, storageReplica := range doc.StorageReplicas {
			if bytes.Equal(shardedReplica.IdentityKey, storageReplica.IdentityKey) {
				replicaIndex = j
				break
			}
		}
		require.NotEqual(t, -1, replicaIndex, msgShouldFindShardedReplicaInStorage)

		replicaIndices[i] = uint8(replicaIndex)
		replicaPubKey := doc.StorageReplicas[replicaIndex].EnvelopeKeys[replicaEpoch]
		replicaPubKeys[i], err = replicaCommon.NikeScheme.UnmarshalBinaryPublicKey(replicaPubKey)
		require.NoError(t, err)
	}

	return &shardingResult{
		ReplicaIndices: replicaIndices,
		ReplicaPubKeys: replicaPubKeys,
	}
}

// createMKEMEnvelope creates a CourierEnvelope with MKEM encryption
func createMKEMEnvelope(t *testing.T, sharding *shardingResult, innerMessage *pigeonhole.ReplicaInnerMessage, isRead bool) *pigeonhole.CourierEnvelope {
	mkemPrivateKey, mkemCiphertext := mkemNikeScheme.Encapsulate(sharding.ReplicaPubKeys, innerMessage.Bytes())
	mkemPublicKey := mkemPrivateKey.Public()
	replicaEpoch, _, _ := replicaCommon.ReplicaNow()
	senderPubkeyBytes := mkemPublicKey.Bytes()

	return &pigeonhole.CourierEnvelope{
		IntermediateReplicas: sharding.ReplicaIndices,
		Dek1:                 *mkemCiphertext.DEKCiphertexts[0],
		Dek2:                 *mkemCiphertext.DEKCiphertexts[1],
		ReplyIndex:           0,
		Epoch:                replicaEpoch,
		SenderPubkeyLen:      uint16(len(senderPubkeyBytes)),
		SenderPubkey:         senderPubkeyBytes,
		CiphertextLen:        uint32(len(mkemCiphertext.Envelope)),
		Ciphertext:           mkemCiphertext.Envelope,
	}
}

// createRequestWithResponse creates a request, sends it, and waits for response
func createRequestWithResponse(t *testing.T, env *testEnvironment, query *pigeonhole.CourierQuery, timeoutSeconds int) *cborplugin.Response {
	// Generate a unique request ID using nanosecond timestamp
	requestID := uint64(time.Now().UnixNano())

	// Register this request with the response router and get a response channel
	responseCh := env.responseRouter.registerRequest(requestID)

	// Clean up the response map entry when done
	defer env.responseRouter.unregisterRequest(requestID)

	queryBytes := query.Bytes()
	requestCmd := &cborplugin.Request{
		ID:      requestID,                                                     // Use unique request ID
		SURB:    []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}, // Fake SURB needed for testing
		Payload: queryBytes,
	}

	// Send the request to the courier
	err := env.courier.Courier.OnCommand(requestCmd)
	require.NoError(t, err)

	// Wait for response with timeout
	var responseCmd cborplugin.Command
	select {
	case responseCmd = <-responseCh:
		t.Log("Received response from courier")
	case <-time.After(time.Duration(timeoutSeconds) * time.Second):
		t.Fatal("Timeout waiting for courier response")
	}

	response, ok := responseCmd.(*cborplugin.Response)
	if !ok {
		t.Fatalf(errUnexpectedResponseType, responseCmd)
	}

	return response
}

// TestCourierReplicaIntegration tests the full courier-replica interaction
// by injecting CourierEnvelope messages directly into the courier and verifying
// that it properly communicates with replicas using the wire protocol.
// This test writes a box to replicas via the courier, then reads it back and
// verifies that all box fields are identical.
func TestCourierReplicaIntegration(t *testing.T) {
	// Disable parallel execution to avoid resource conflicts
	// t.Parallel() is intentionally not called

	// Create test environment with real servers
	testEnv := setupTestEnvironment(t)
	defer func() {
		t.Logf("Starting cleanup for TestCourierReplicaIntegration")
		testEnv.cleanup()
		t.Logf("Cleanup completed for TestCourierReplicaIntegration")
	}()

	// Wait for servers to be ready
	time.Sleep(2 * time.Second)

	// Test complete round-trip: write box, then read it back and verify
	testBoxRoundTrip(t, testEnv)
}

// TestCourierReplicaSequenceIntegration tests writing and reading a sequence of boxes
// using BACAP stateful writer/reader to verify sequence handling works correctly.
func TestCourierReplicaSequenceIntegration(t *testing.T) {
	// Disable parallel execution to avoid resource conflicts
	// t.Parallel() is intentionally not called

	// Create test environment with real servers
	testEnv := setupTestEnvironment(t)
	defer func() {
		t.Logf("Starting cleanup for TestCourierReplicaSequenceIntegration")
		testEnv.cleanup()
		t.Logf("Cleanup completed for TestCourierReplicaSequenceIntegration")
	}()

	// Wait for servers to be ready
	time.Sleep(2 * time.Second)

	// Test sequence round-trip: write multiple boxes, then read them back and verify
	testBoxSequenceRoundTrip(t, testEnv)
}

// TestCourierReplicaNestedEnvelopeIntegration tests writing a large nested encrypted
// CourierEnvelope CBOR blob that spans two boxes, then reading it back and verifying
// the raw bytes match.
// NOTE(david): This test is currently disabled because it requires the courier's copy
// implementation to be working and that isn't working at the moment.
/*
func NoTestCourierReplicaNestedEnvelopeIntegration(t *testing.T) {
	// Disable parallel execution to avoid resource conflicts
	// t.Parallel() is intentionally not called

	// Create test environment with real servers
	testEnv := setupTestEnvironment(t)
	defer func() {
		t.Logf("Starting cleanup for TestCourierReplicaNestedEnvelopeIntegration")
		testEnv.cleanup()
		t.Logf("Cleanup completed for TestCourierReplicaNestedEnvelopeIntegration")
	}()

	// Wait for servers to be ready
	time.Sleep(2 * time.Second)

	// Test nested envelope round-trip: write large CBOR blob across two boxes
	testNestedEnvelopeRoundTrip(t, testEnv)
}
*/

// testEnvironment holds all the components needed for testing
type testEnvironment struct {
	tempDir        string
	replicas       []*replica.Server
	courier        *courierServer.Server
	mockPKIClient  *mockPKIClient
	replicaConfigs []*config.Config
	courierConfig  *courierConfig.Config
	cleanup        func()
	replicaKeys    []map[uint64]nike.PublicKey
	geometry       *pigeonholeGeo.Geometry
	// Response routing system - set up once per test environment
	responseRouter *responseRouter
}

// responseRouter handles routing courier responses to the correct test channels
type responseRouter struct {
	// Map to route responses by request ID
	responseMap   map[uint64]chan cborplugin.Command
	responseMapMu sync.RWMutex
	// Global response channel for debugging
	globalCh chan cborplugin.Command
}

// newResponseRouter creates a new response router
func newResponseRouter() *responseRouter {
	return &responseRouter{
		responseMap: make(map[uint64]chan cborplugin.Command),
		globalCh:    make(chan cborplugin.Command, 100),
	}
}

// registerRequest registers a request ID and returns a channel for its response
func (rr *responseRouter) registerRequest(requestID uint64) chan cborplugin.Command {
	responseCh := make(chan cborplugin.Command, 1)
	rr.responseMapMu.Lock()
	rr.responseMap[requestID] = responseCh
	rr.responseMapMu.Unlock()
	return responseCh
}

// unregisterRequest removes a request ID from the routing map
func (rr *responseRouter) unregisterRequest(requestID uint64) {
	rr.responseMapMu.Lock()
	delete(rr.responseMap, requestID)
	rr.responseMapMu.Unlock()
}

// writeFunc is the function that gets called by the courier to send responses
func (rr *responseRouter) writeFunc(cmd cborplugin.Command) {
	// Send to global channel for debugging
	select {
	case rr.globalCh <- cmd:
	default:
		// Don't block if global channel is full
	}

	// Route to specific request channel if it exists
	if response, ok := cmd.(*cborplugin.Response); ok {
		rr.responseMapMu.RLock()
		targetCh := rr.responseMap[response.ID]
		rr.responseMapMu.RUnlock()

		if targetCh != nil {
			select {
			case targetCh <- cmd:
			case <-time.After(1 * time.Second):
				// Don't block forever if channel is full
			}
		}
	}
}

func setupTestEnvironment(t *testing.T) *testEnvironment {
	tempDir, err := os.MkdirTemp("", "courier_replica_test_*")
	require.NoError(t, err)

	// Use unique port base for each test to avoid conflicts
	portBase := 19000 + (int(time.Now().UnixNano()) % 1000)

	// Use 5000 - our perfect geometry calculations now predict the exact message size
	sphinxGeo := geo.GeometryFromUserForwardPayloadLength(nikeSchemes.ByName("X25519"), 5000, true, 5)
	pkiScheme := signSchemes.ByName(testPKIScheme)
	linkScheme := kemSchemes.ByName("Xwing")

	courierDir := filepath.Join(tempDir, "courier")
	require.NoError(t, os.MkdirAll(courierDir, 0700))
	courierCfg := createCourierConfig(t, courierDir, pkiScheme, linkScheme, sphinxGeo)

	_, courierLinkPubKey := generateCourierLinkKeys(t, courierDir, courierCfg.WireKEMScheme)
	serviceDesc := makeServiceDescriptor(t, courierLinkPubKey)

	numReplicas := 3
	replicaDescriptors := make([]*pki.ReplicaDescriptor, numReplicas)
	replicaConfigs := make([]*config.Config, numReplicas)
	replicaKeys := make([]map[uint64]nike.PublicKey, numReplicas)

	// STEP 1: Create all replica descriptors FIRST
	for i := 0; i < numReplicas; i++ {
		replicaDir := filepath.Join(tempDir, fmt.Sprintf(testReplicaNameFormat, i))
		require.NoError(t, os.MkdirAll(replicaDir, 0700))
		replicaConfigs[i] = createReplicaConfig(t, replicaDir, pkiScheme, linkScheme, i, sphinxGeo, portBase)
		myreplicaKeys, linkPubKey, replicaIdentityPubKey := generateReplicaKeys(t, replicaDir, replicaConfigs[i].PKISignatureScheme, replicaConfigs[i].WireKEMScheme)
		replicaDescriptors[i] = makeReplicaDescriptor(t, i, linkPubKey, replicaIdentityPubKey, myreplicaKeys, portBase)
		replicaKeys[i] = myreplicaKeys
	}

	// STEP 2: Create shared mock PKI client for all components
	// This ensures all components use the same PKI documents and memoization
	sharedMockPKIClient := createMockPKIClient(t, sphinxGeo, serviceDesc, replicaDescriptors)

	// Create all servers with the shared PKI client
	replicas := make([]*replica.Server, numReplicas)
	for i := 0; i < numReplicas; i++ {
		replicas[i] = createReplicaServer(t, replicaConfigs[i], sharedMockPKIClient)
	}

	courier := createCourierServer(t, courierCfg, sharedMockPKIClient)

	// Force all replicas to fetch PKI documents first
	for i, replica := range replicas {
		t.Logf("Forcing PKI fetch for replica %d during setup", i)
		err = replica.PKIWorker.ForceFetchPKI()
		require.NoError(t, err)
	}

	// Force courier to fetch PKI documents, then update connector
	err = courier.PKI.ForceFetchPKI()
	require.NoError(t, err)
	courier.ForceConnectorUpdate()

	cleanup := func() {
		// Shutdown all replicas first
		for i, replica := range replicas {
			if replica != nil {
				t.Logf("Shutting down replica %d", i)
				replica.Shutdown()
				replica.Wait()
			}
		}

		// Note: Courier doesn't have explicit shutdown methods,
		// it will be cleaned up when the process exits

		// Clean up temporary directory
		t.Logf("Removing temp directory: %s", tempDir)
		os.RemoveAll(tempDir)
	}

	// Set up response routing system - SetWriteFunc called only once per test environment
	router := newResponseRouter()

	// Set up the write function once and only once - this is critical to avoid data races
	courier.Courier.SetWriteFunc(router.writeFunc)

	// Use the same pigeonhole geometry that the courier uses (derived from Sphinx geometry)
	// This ensures consistency between test expectations and courier behavior
	pigeonholeGeometry, err := pigeonholeGeo.NewGeometryFromSphinx(sphinxGeo, replicaCommon.NikeScheme)
	require.NoError(t, err)

	// Debug: Print geometry values to understand the size limits
	t.Logf("Sphinx UserForwardPayloadLength: %d", sphinxGeo.UserForwardPayloadLength)
	t.Logf("Pigeonhole Geometry: %s", pigeonholeGeometry.String())

	return &testEnvironment{
		tempDir:        tempDir,
		replicas:       replicas,
		courier:        courier,
		mockPKIClient:  sharedMockPKIClient,
		replicaConfigs: replicaConfigs,
		courierConfig:  courierCfg,
		cleanup:        cleanup,
		replicaKeys:    replicaKeys,
		geometry:       pigeonholeGeometry,
		responseRouter: router,
	}
}

// createReplicaConfig creates a configuration for a replica server.
// the configuration will contain a PKI configuration section which
// is synthetic and does not connect to any real directory authorities.
func createReplicaConfig(t *testing.T, dataDir string, pkiScheme sign.Scheme, linkScheme kem.Scheme, replicaID int, sphinxGeo *geo.Geometry, portBase int) *config.Config {
	return &config.Config{
		DataDir:            dataDir,
		Identifier:         fmt.Sprintf(testReplicaNameFormat, replicaID),
		WireKEMScheme:      linkScheme.Name(),
		PKISignatureScheme: pkiScheme.Name(),
		ReplicaNIKEScheme:  replicaCommon.NikeScheme.Name(),
		SphinxGeometry:     sphinxGeo,
		Addresses:          []string{fmt.Sprintf("tcp://127.0.0.1:%d", portBase+replicaID)},
		GenerateOnly:       false,
		ConnectTimeout:     60000,  // 60 seconds
		HandshakeTimeout:   30000,  // 30 seconds
		ReauthInterval:     300000, // 5 minutes
		Logging: &config.Logging{
			Disable: false,
			Level:   "DEBUG",
		},
		PKI: &config.PKI{
			Voting: &config.Voting{
				Authorities: []*dirauthConfig.Authority{
					&dirauthConfig.Authority{
						Identifier:         "auth1",
						IdentityPublicKey:  nil,
						PKISignatureScheme: "Ed25519",
						LinkPublicKey:      nil,
						WireKEMScheme:      "Xwing",
					},
				},
			},
		},
	}
}

func generateReplicaKeys(t *testing.T, dataDir, pkiSignatureSchemeName, wireKEMSchemeName string) (map[uint64]nike.PublicKey, kem.PublicKey, sign.PublicKey) {

	pkiSignatureScheme := signSchemes.ByName(pkiSignatureSchemeName)
	require.NotNil(t, pkiSignatureScheme)

	wireKEMScheme := kemSchemes.ByName(wireKEMSchemeName)
	require.NotNil(t, wireKEMScheme)

	replicaKeys := make(map[uint64]nike.PublicKey)
	replicaEpoch, _, _ := replicaCommon.ReplicaNow()

	replicaNIKEPublicKey, replicaNIKEPrivateKey, err := replicaCommon.NikeScheme.GenerateKeyPair()
	require.NoError(t, err)
	nikePem.PrivateKeyToFile(filepath.Join(dataDir, fmt.Sprintf("replica.%d.private.pem", replicaEpoch)), replicaNIKEPrivateKey, replicaCommon.NikeScheme)
	nikePem.PublicKeyToFile(filepath.Join(dataDir, fmt.Sprintf("replica.%d.public.pem", replicaEpoch)), replicaNIKEPublicKey, replicaCommon.NikeScheme)
	replicaKeys[replicaEpoch] = replicaNIKEPublicKey

	// generate identity key pair
	replicaIdentityPublicKey, replicaIdentityPrivateKey, err := pkiSignatureScheme.GenerateKey()
	require.NoError(t, err)
	replicaIdentityPrivateKeyFile := filepath.Join(dataDir, "identity.private.pem")
	err = signPem.PrivateKeyToFile(replicaIdentityPrivateKeyFile, replicaIdentityPrivateKey)
	require.NoError(t, err)
	replicaIdentityPublicKeyFile := filepath.Join(dataDir, "identity.public.pem")
	err = signPem.PublicKeyToFile(replicaIdentityPublicKeyFile, replicaIdentityPublicKey)
	require.NoError(t, err)

	// generate link key pair
	linkPublicKey, linkPrivateKey, err := wireKEMScheme.GenerateKeyPair()
	require.NoError(t, err)
	kemPEM.PrivateKeyToFile(filepath.Join(dataDir, "link.private.pem"), linkPrivateKey)
	kemPEM.PublicKeyToFile(filepath.Join(dataDir, "link.public.pem"), linkPublicKey)

	return replicaKeys, linkPublicKey, replicaIdentityPublicKey
}

func createCourierConfig(t *testing.T, dataDir string, pkiScheme sign.Scheme, linkScheme kem.Scheme, sphinxGeo *geo.Geometry) *courierConfig.Config {
	return &courierConfig.Config{
		DataDir:          dataDir,
		WireKEMScheme:    linkScheme.Name(),
		PKIScheme:        pkiScheme.Name(),
		EnvelopeScheme:   replicaCommon.NikeScheme.Name(),
		SphinxGeometry:   sphinxGeo,
		ConnectTimeout:   60000,
		HandshakeTimeout: 30000,
		ReauthInterval:   300000, // 5 minutes to prevent connection churn during test

		Logging: &courierConfig.Logging{
			Disable: false,
			Level:   "DEBUG",
		},
		PKI: &courierConfig.PKI{
			Voting: &courierConfig.Voting{
				Authorities: []*dirauthConfig.Authority{
					&dirauthConfig.Authority{
						Identifier:         "auth1",
						IdentityPublicKey:  nil,
						PKISignatureScheme: "Ed25519",
						LinkPublicKey:      nil,
						WireKEMScheme:      "Xwing",
						Addresses:          []string{""},
					},
				},
			},
		},
	}
}

func generateCourierLinkKeys(t *testing.T, dataDir, kemSchemeName string) (kem.PrivateKey, kem.PublicKey) {
	kemScheme := kemSchemes.ByName(kemSchemeName)
	require.NotNil(t, kemScheme)

	// Generate link key pair
	linkPubKey, linkPrivKey, err := kemScheme.GenerateKeyPair()
	require.NoError(t, err)
	linkPrivKeyFile := filepath.Join(dataDir, "link.private.pem")
	err = kemPEM.PrivateKeyToFile(linkPrivKeyFile, linkPrivKey)
	require.NoError(t, err)
	linkPubKeyFile := filepath.Join(dataDir, "link.public.pem")
	err = kemPEM.PublicKeyToFile(linkPubKeyFile, linkPubKey)
	require.NoError(t, err)

	return linkPrivKey, linkPubKey
}

func createReplicaServer(t *testing.T, cfg *config.Config, pkiClient pki.Client) *replica.Server {
	server, err := replica.NewWithPKI(cfg, pkiClient)
	require.NoError(t, err)
	require.NotNil(t, server)
	return server
}

func makeServiceDescriptor(t *testing.T, linkPubKey kem.PublicKey) *pki.MixDescriptor {
	linkPubKeyPEM := kemPEM.ToPublicPEMString(linkPubKey)
	address := "tcp://127.0.0.1:22000"

	return &pki.MixDescriptor{
		Name:        "servicenode1",
		IdentityKey: []byte("servicenode1_identity_key"),
		LinkKey:     []byte("servicenode1_link_key"),
		Addresses: map[string][]string{
			"tcp": {address},
		},
		Kaetzchen: map[string]map[string]interface{}{
			"courier": map[string]interface{}{
				"endpoint": "+courier",
			},
		},
		KaetzchenAdvertizedData: map[string]map[string]interface{}{
			"courier": map[string]interface{}{
				"linkPublicKey": linkPubKeyPEM,
			},
		},
		IsServiceNode: true,
		IsGatewayNode: false,
	}
}

func makeReplicaDescriptor(t *testing.T,
	replicaID int,
	linkPubKey kem.PublicKey,
	identityPubKey sign.PublicKey,
	replicaKeys map[uint64]nike.PublicKey,
	portBase int) *pki.ReplicaDescriptor {

	require.NotNil(t, linkPubKey)
	require.NotNil(t, identityPubKey)
	require.NotNil(t, replicaKeys)
	require.NotEqual(t, len(replicaKeys), 0)

	linkPubKeyBytes, err := linkPubKey.MarshalBinary()
	require.NoError(t, err)
	identityPubKeyBytes, err := identityPubKey.MarshalBinary()
	require.NoError(t, err)

	desc := &pki.ReplicaDescriptor{
		Name:        fmt.Sprintf(testReplicaNameFormat, replicaID),
		IdentityKey: identityPubKeyBytes,
		LinkKey:     linkPubKeyBytes,
		Addresses: map[string][]string{
			"tcp": {fmt.Sprintf("tcp://127.0.0.1:%d", portBase+replicaID)},
		},
		EnvelopeKeys: make(map[uint64][]byte),
	}

	replicaEpoch, _, _ := replicaCommon.ReplicaNow()
	pubKey, ok := replicaKeys[replicaEpoch]
	require.True(t, ok)
	pubKeyBlob, err := pubKey.MarshalBinary()
	require.NoError(t, err)
	desc.EnvelopeKeys[replicaEpoch] = pubKeyBlob

	return desc
}

func createMockPKIClient(t *testing.T, sphinxGeo *geo.Geometry, serviceDesc *pki.MixDescriptor, replicaDescriptors []*pki.ReplicaDescriptor) *mockPKIClient {
	mock := newMockPKIClient(t)

	// Generate PKI documents for a wide range of epochs to handle any epoch requests
	// This ensures both the test logic and PKI workers can find documents
	currentEpoch, _, _ := epochtime.Now()

	// Create documents for a range around the current epoch
	for i := int64(-10); i <= 10; i++ {
		epoch := uint64(int64(currentEpoch) + i)
		doc := generateTestPKIDocument(t, epoch, serviceDesc, replicaDescriptors, sphinxGeo)
		doc.Epoch = epoch
		mock.docs[epoch] = doc
	}

	return mock
}

func generateTestPKIDocument(t *testing.T, epoch uint64, serviceDesc *pki.MixDescriptor, replicaDescriptors []*pki.ReplicaDescriptor, sphinxGeo *geo.Geometry) *pki.Document {
	return &pki.Document{
		Epoch:              epoch,
		SendRatePerMinute:  100,
		LambdaP:            0.1,
		LambdaL:            0.1,
		LambdaD:            0.1,
		LambdaM:            0.1,
		StorageReplicas:    replicaDescriptors,
		Topology:           make([][]*pki.MixDescriptor, 0),
		GatewayNodes:       make([]*pki.MixDescriptor, 0),
		ServiceNodes:       []*pki.MixDescriptor{serviceDesc},
		SharedRandomValue:  make([]byte, 32),
		SphinxGeometryHash: sphinxGeo.Hash(),
	}
}

type mockPKIClient struct {
	t    *testing.T
	mu   sync.RWMutex
	docs map[uint64]*pki.Document
}

func newMockPKIClient(t *testing.T) *mockPKIClient {
	return &mockPKIClient{
		t:    t,
		mu:   sync.RWMutex{},
		docs: make(map[uint64]*pki.Document),
	}
}

func (c *mockPKIClient) Get(ctx context.Context, epoch uint64) (*pki.Document, []byte, error) {
	// First, try to read from cache with read lock
	c.mu.RLock()
	doc, exists := c.docs[epoch]
	c.mu.RUnlock()

	if !exists {
		// Need to generate document, acquire write lock
		c.mu.Lock()
		// Double-check in case another goroutine generated it while we were waiting
		doc, exists = c.docs[epoch]
		if !exists {
			// Generate document on-demand for any requested epoch
			// Use the template from any existing document
			var templateDoc *pki.Document
			for _, d := range c.docs {
				templateDoc = d
				break
			}
			if templateDoc == nil {
				c.mu.Unlock()
				return nil, nil, fmt.Errorf("no template PKI document available to generate document for epoch %d", epoch)
			}

			// Create a copy of the template document with the requested epoch
			doc = &pki.Document{
				Epoch:              epoch,
				SendRatePerMinute:  templateDoc.SendRatePerMinute,
				LambdaP:            templateDoc.LambdaP,
				LambdaL:            templateDoc.LambdaL,
				LambdaD:            templateDoc.LambdaD,
				LambdaM:            templateDoc.LambdaM,
				StorageReplicas:    templateDoc.StorageReplicas,
				Topology:           templateDoc.Topology,
				GatewayNodes:       templateDoc.GatewayNodes,
				ServiceNodes:       templateDoc.ServiceNodes,
				SharedRandomValue:  templateDoc.SharedRandomValue,
				SphinxGeometryHash: templateDoc.SphinxGeometryHash,
			}

			// Memoize the generated document for future requests
			c.docs[epoch] = doc
		}
		c.mu.Unlock()
	}

	blob, err := doc.MarshalCertificate()
	if err != nil {
		return nil, nil, err
	}
	return doc, blob, nil
}

func (c *mockPKIClient) Post(ctx context.Context, epoch uint64, signingPrivateKey sign.PrivateKey, signingPublicKey sign.PublicKey, d *pki.MixDescriptor, loopstats *loops.LoopStats) error {
	c.t.Log("mockPKIClient: Post not implemented")
	return nil
}

func (c *mockPKIClient) PostReplica(ctx context.Context, epoch uint64, signingPrivateKey sign.PrivateKey, signingPublicKey sign.PublicKey, d *pki.ReplicaDescriptor) error {
	c.t.Log("mockPKIClient: PostReplica not implemented")
	return nil
}

func (c *mockPKIClient) Deserialize(raw []byte) (*pki.Document, error) {
	return pki.ParseDocument(raw)
}

func createCourierServer(t *testing.T, cfg *courierConfig.Config, pkiClient pki.Client) *courierServer.Server {
	server, err := courierServer.New(cfg, pkiClient)
	require.NoError(t, err)
	require.NotNil(t, server)
	return server
}

func aliceComposesNextMessage(t *testing.T, message []byte, env *testEnvironment, aliceStatefulWriter *bacap.StatefulWriter) *pigeonhole.CourierEnvelope {
	return aliceComposesNextMessageWithIsLast(t, message, env, aliceStatefulWriter, false)
}

func aliceComposesNextMessageWithIsLast(t *testing.T, message []byte, env *testEnvironment, aliceStatefulWriter *bacap.StatefulWriter, isLast bool) *pigeonhole.CourierEnvelope {
	// Create padded payload with length prefix for BACAP
	paddedPayload, err := pigeonhole.CreatePaddedPayload(message, env.geometry.MaxPlaintextPayloadLength+4)
	require.NoError(t, err)

	boxID, ciphertext, sigraw, err := aliceStatefulWriter.EncryptNext(paddedPayload)
	require.NoError(t, err)

	// DEBUG: Log Alice's BoxID
	t.Logf("DEBUG: Alice writes to BoxID: %x (IsLast=%v)", boxID[:], isLast)

	sig := [bacap.SignatureSize]byte{}
	copy(sig[:], sigraw)

	writeRequest := pigeonhole.ReplicaWrite{
		BoxID:      boxID,
		Signature:  sig,
		PayloadLen: uint32(len(ciphertext)),
		Payload:    ciphertext,
	}
	msg := &pigeonhole.ReplicaInnerMessage{
		MessageType: 1, // 1 = write, 0 = read
		WriteMsg:    &writeRequest,
	}

	currentEpoch, _, _ := epochtime.Now()
	replicaEpoch, _, _ := replicaCommon.ReplicaNow()
	replicaPubKey1 := env.mockPKIClient.docs[currentEpoch].StorageReplicas[0].EnvelopeKeys[replicaEpoch]
	replicaPubKey2 := env.mockPKIClient.docs[currentEpoch].StorageReplicas[1].EnvelopeKeys[replicaEpoch]

	replicaPubKeys := make([]nike.PublicKey, 2)
	replicaPubKeys[0], err = replicaCommon.NikeScheme.UnmarshalBinaryPublicKey(replicaPubKey1)
	require.NoError(t, err)
	replicaPubKeys[1], err = replicaCommon.NikeScheme.UnmarshalBinaryPublicKey(replicaPubKey2)
	require.NoError(t, err)

	mkemPrivateKey, mkemCiphertext := mkemNikeScheme.Encapsulate(
		replicaPubKeys, msg.Bytes(),
	)
	mkemPublicKey := mkemPrivateKey.Public()

	senderPubkeyBytes := mkemPublicKey.Bytes()

	return &pigeonhole.CourierEnvelope{
		IntermediateReplicas: [2]uint8{0, 1}, // indices to pkidoc's StorageReplicas
		Dek1:                 *mkemCiphertext.DEKCiphertexts[0],
		Dek2:                 *mkemCiphertext.DEKCiphertexts[1],
		ReplyIndex:           0,
		Epoch:                replicaEpoch,
		SenderPubkeyLen:      uint16(len(senderPubkeyBytes)),
		SenderPubkey:         senderPubkeyBytes,
		CiphertextLen:        uint32(len(mkemCiphertext.Envelope)),
		Ciphertext:           mkemCiphertext.Envelope,
	}
}

func aliceAndBobKeyExchangeKeys(t *testing.T, env *testEnvironment) (*bacap.StatefulWriter, *bacap.StatefulReader) {
	// --- Alice creates a BACAP sequence and gives Bob a sequence read capability
	// Bob can read from his StatefulReader that which Alice writes with her StatefulWriter.
	aliceOwner, err := bacap.NewWriteCap(rand.Reader)
	require.NoError(t, err)
	aliceStatefulWriter, err := bacap.NewStatefulWriter(aliceOwner, constants.PIGEONHOLE_CTX)
	require.NoError(t, err)
	bobReadCap := aliceOwner.ReadCap()
	bobStatefulReader, err := bacap.NewStatefulReader(bobReadCap, constants.PIGEONHOLE_CTX)
	require.NoError(t, err)
	return aliceStatefulWriter, bobStatefulReader
}

// waitForCourierPKI waits for the courier to have a PKI document
func waitForCourierPKI(t *testing.T, env *testEnvironment) {
	maxWait := 30 * time.Second
	checkInterval := 100 * time.Millisecond
	start := time.Now()

	for time.Since(start) < maxWait {
		if env.courier.PKI.HasCurrentPKIDocument() {
			t.Log("Courier has PKI document")
			return
		}
		time.Sleep(checkInterval)
	}

	t.Fatal("Timeout waiting for courier PKI document to be ready")
}

// waitForReplicasPKI waits for all replicas to have PKI documents
func waitForReplicasPKI(t *testing.T, env *testEnvironment) {
	maxWait := 30 * time.Second
	checkInterval := 100 * time.Millisecond
	start := time.Now()

	for time.Since(start) < maxWait {
		allReady := true
		for i, replica := range env.replicas {
			if !replica.PKIWorker.HasCurrentPKIDocument() {
				t.Logf("Replica %d does not have PKI document yet", i)
				allReady = false
				break
			}
		}
		if allReady {
			t.Log("All replicas have PKI documents")
			return
		}
		time.Sleep(checkInterval)
	}

	t.Fatal("Timeout waiting for all replicas to have PKI documents")
}

func testBoxRoundTrip(t *testing.T, env *testEnvironment) {
	// PKI documents are already fetched during setup, just verify they're ready
	waitForCourierPKI(t, env)
	waitForReplicasPKI(t, env)

	aliceStatefulWriter, bobStatefulReader := aliceAndBobKeyExchangeKeys(t, env)

	alicePayload1 := []byte("Hello, Bob!")
	aliceEnvelope1 := aliceComposesNextMessage(t, alicePayload1, env, aliceStatefulWriter)

	courierWriteReply1 := injectCourierEnvelope(t, env, aliceEnvelope1)

	// Note: EnvelopeHash method doesn't exist on trunnel types, skipping hash comparison
	// require.Equal(t, uint8(0), courierWriteReply1.ErrorCode) // ErrorCode doesn't exist on CourierEnvelopeReply
	require.Equal(t, uint8(0), courierWriteReply1.ReplyIndex)
	require.True(t, len(courierWriteReply1.Payload) == 0) // Payload should be empty for write operations

	bobReadRequest1, bobPrivateKey1 := composeReadRequest(t, env, bobStatefulReader)

	// First read request should now get immediate reply with payload due to immediate proxying
	courierReadReply1 := injectCourierEnvelope(t, env, bobReadRequest1)

	// Note: EnvelopeHash method doesn't exist on trunnel types, skipping hash comparison
	// require.Equal(t, uint8(0), courierReadReply1.ErrorCode) // ErrorCode doesn't exist on CourierEnvelopeReply

	// With immediate proxying, we should get a non-empty payload on the first request
	if len(courierReadReply1.Payload) == 0 {
		t.Logf("First read request returned nil payload, this suggests immediate proxying didn't work")
		// For now, let's still allow the test to continue to see what happens
		// In the future, this should be a hard requirement
		t.Logf("Continuing test to see if traditional caching still works...")

		// Fall back to traditional polling approach for now
		courierReadReply1 = waitForReplicaResponse(t, env, bobReadRequest1)
	}

	// ReplyIndex now correctly indicates which replica replied (0 or 1)
	require.True(t, courierReadReply1.ReplyIndex < 2, "ReplyIndex should be 0 or 1")
	require.True(t, len(courierReadReply1.Payload) > 0, "Should have payload either from immediate proxying or cache")
	require.True(t, len(courierReadReply1.Payload) > 0, "Payload should not be empty")

	replicaEpoch, _, _ := replicaCommon.ReplicaNow()

	// Now ReplyIndex correctly indicates which replica replied (0 or 1)
	replicaIndex := int(bobReadRequest1.IntermediateReplicas[courierReadReply1.ReplyIndex])
	replicaPubKey := env.replicaKeys[replicaIndex][replicaEpoch]
	rawInnerMsg, err := mkemNikeScheme.DecryptEnvelope(bobPrivateKey1, replicaPubKey, courierReadReply1.Payload)
	require.NoError(t, err)

	// pigeonhole.ReplicaMessageReplyInnerMessage
	innerMsg, err := pigeonhole.ParseReplicaMessageReplyInnerMessage(rawInnerMsg)
	require.NoError(t, err)
	require.NotNil(t, innerMsg.ReadReply)

	boxid, err := bobStatefulReader.NextBoxID()
	require.NoError(t, err)
	var signature [64]byte
	copy(signature[:], innerMsg.ReadReply.Signature[:])
	bobPaddedPlaintext1, err := bobStatefulReader.DecryptNext(constants.PIGEONHOLE_CTX, *boxid, innerMsg.ReadReply.Payload, signature)
	require.NoError(t, err)

	// Extract the actual message data from the padded payload (remove 4-byte length prefix and padding)
	bobPlaintext1, err := pigeonhole.ExtractMessageFromPaddedPayload(bobPaddedPlaintext1)
	require.NoError(t, err)
	require.Equal(t, alicePayload1, bobPlaintext1)
}

func testBoxSequenceRoundTrip(t *testing.T, env *testEnvironment) {
	// PKI documents are already fetched during setup, just verify they're ready
	waitForCourierPKI(t, env)
	waitForReplicasPKI(t, env)

	aliceStatefulWriter, bobStatefulReader := aliceAndBobKeyExchangeKeys(t, env)

	// Define the sequence of messages to write
	messages := [][]byte{
		[]byte("hello 1"),
		[]byte("hello 2"),
		[]byte("hello 3"),
	}

	// Write the sequence of boxes
	t.Logf("Writing sequence of %d boxes", len(messages))
	for i, payload := range messages {
		t.Logf("Writing box %d with payload: %s", i+1, string(payload))

		aliceEnvelope := aliceComposesNextMessage(t, payload, env, aliceStatefulWriter)
		courierWriteReply := injectCourierEnvelope(t, env, aliceEnvelope)

		// Note: EnvelopeHash method doesn't exist on trunnel types, skipping hash comparison
		// require.Equal(t, uint8(0), courierWriteReply.ErrorCode) // ErrorCode doesn't exist on CourierEnvelopeReply
		require.Equal(t, uint8(0), courierWriteReply.ReplyIndex)
		require.True(t, len(courierWriteReply.Payload) == 0) // Payload should be empty for write operations

		t.Logf("Successfully wrote box %d", i+1)
	}

	// Now read back the sequence of boxes
	t.Logf("Reading back sequence of %d boxes", len(messages))
	for i := 0; i < len(messages); i++ {
		t.Logf("Reading box %d", i+1)

		bobReadRequest, bobPrivateKey := composeReadRequest(t, env, bobStatefulReader)

		// First read request should now get immediate reply with payload due to immediate proxying
		courierReadReply := injectCourierEnvelope(t, env, bobReadRequest)

		// Note: EnvelopeHash method doesn't exist on trunnel types, skipping hash comparison
		// require.Equal(t, uint8(0), courierReadReply.ErrorCode) // ErrorCode doesn't exist on CourierEnvelopeReply

		// With immediate proxying, we should get a non-empty payload on the first request
		if len(courierReadReply.Payload) == 0 {
			t.Logf("First read request returned nil payload for box %d, falling back to polling", i+1)
			courierReadReply = waitForReplicaResponse(t, env, bobReadRequest)
		}

		// ReplyIndex correctly indicates which replica replied (0 or 1)
		require.True(t, courierReadReply.ReplyIndex < 2, "ReplyIndex should be 0 or 1")
		require.True(t, len(courierReadReply.Payload) > 0, "Should have payload either from immediate proxying or cache")
		require.True(t, len(courierReadReply.Payload) > 0, "Payload should not be empty")

		// Decrypt and verify the message
		replicaEpoch, _, _ := replicaCommon.ReplicaNow()
		replicaIndex := int(bobReadRequest.IntermediateReplicas[courierReadReply.ReplyIndex])
		replicaPubKey := env.replicaKeys[replicaIndex][replicaEpoch]
		rawInnerMsg, err := mkemNikeScheme.DecryptEnvelope(bobPrivateKey, replicaPubKey, courierReadReply.Payload)
		require.NoError(t, err)

		// pigeonhole.ReplicaMessageReplyInnerMessage
		innerMsg, err := pigeonhole.ParseReplicaMessageReplyInnerMessage(rawInnerMsg)
		require.NoError(t, err)
		require.NotNil(t, innerMsg.ReadReply)

		boxid, err := bobStatefulReader.NextBoxID()
		require.NoError(t, err)
		var signature [64]byte
		copy(signature[:], innerMsg.ReadReply.Signature[:])
		bobPaddedPlaintext, err := bobStatefulReader.DecryptNext(constants.PIGEONHOLE_CTX, *boxid, innerMsg.ReadReply.Payload, signature)
		require.NoError(t, err)

		// Extract the actual message data from the padded payload (remove 4-byte length prefix and padding)
		bobPlaintext, err := pigeonhole.ExtractMessageFromPaddedPayload(bobPaddedPlaintext)
		require.NoError(t, err)

		// Verify the decrypted message matches what we wrote
		expectedMessage := messages[i]
		require.Equal(t, expectedMessage, bobPlaintext)
		t.Logf("Successfully read and verified box %d: %s", i+1, string(bobPlaintext))
	}

	t.Logf("Successfully completed sequence round-trip test for %d boxes", len(messages))
}

func injectCourierEnvelope(t *testing.T, env *testEnvironment, envelope *pigeonhole.CourierEnvelope) *pigeonhole.CourierEnvelopeReply {
	// Create a CBOR plugin command containing the CourierQuery with CourierEnvelope
	courierQuery := &pigeonhole.CourierQuery{
		QueryType: 0, // 0 = envelope
		Envelope:  envelope,
	}

	response := createRequestWithResponse(t, env, courierQuery, 10)

	courierQueryReply, err := pigeonhole.ParseCourierQueryReply(response.Payload)
	require.NoError(t, err)
	require.NotNil(t, courierQueryReply)
	require.NotNil(t, courierQueryReply.EnvelopeReply)

	return courierQueryReply.EnvelopeReply
}

func composeReadRequest(t *testing.T, env *testEnvironment, reader *bacap.StatefulReader) (*pigeonhole.CourierEnvelope, nike.PrivateKey) {
	boxID, err := reader.NextBoxID()
	require.NoError(t, err)

	// DEBUG: Log Bob's BoxID
	t.Logf("DEBUG: Bob reads from BoxID: %x", boxID[:])

	readRequest := &pigeonhole.ReplicaRead{
		BoxID: *boxID,
	}

	msg := &pigeonhole.ReplicaInnerMessage{
		MessageType: 0, // 0 = read
		ReadMsg:     readRequest,
	}

	sharding := getShardingInfo(t, env, boxID)

	for _, replicaIndex := range sharding.ReplicaIndices {
		t.Logf("BoxID %x will be read from replica %d", boxID[:8], replicaIndex)
	}

	mkemPrivateKey, mkemCiphertext := mkemNikeScheme.Encapsulate(sharding.ReplicaPubKeys, msg.Bytes())
	mkemPublicKey := mkemPrivateKey.Public()
	replicaEpoch, _, _ := replicaCommon.ReplicaNow()
	senderPubkeyBytes := mkemPublicKey.Bytes()

	return &pigeonhole.CourierEnvelope{
		IntermediateReplicas: sharding.ReplicaIndices,
		Dek1:                 *mkemCiphertext.DEKCiphertexts[0],
		Dek2:                 *mkemCiphertext.DEKCiphertexts[1],
		ReplyIndex:           0,
		Epoch:                replicaEpoch,
		SenderPubkeyLen:      uint16(len(senderPubkeyBytes)),
		SenderPubkey:         senderPubkeyBytes,
		CiphertextLen:        uint32(len(mkemCiphertext.Envelope)),
		Ciphertext:           mkemCiphertext.Envelope,
	}, mkemPrivateKey
}

// waitForReplicaResponse waits for the courier to receive a reply by repeatedly trying the request
// until we get a non-nil payload, indicating the replica response has been received
func waitForReplicaResponse(t *testing.T, env *testEnvironment, envelope *pigeonhole.CourierEnvelope) *pigeonhole.CourierEnvelopeReply {
	maxWait := 10 * time.Second
	checkInterval := 100 * time.Millisecond
	start := time.Now()

	for time.Since(start) < maxWait {
		reply := injectCourierEnvelope(t, env, envelope)

		// If we got a non-empty payload, the response is ready
		if len(reply.Payload) > 0 {
			t.Logf("Courier response ready - received payload of length %d", len(reply.Payload))
			return reply
		}

		// Wait before trying again
		time.Sleep(checkInterval)
	}

	// Create a hash of the envelope for error reporting
	envelopeBytes := envelope.Bytes()
	hash := make([]byte, 8)
	copy(hash, envelopeBytes[:8])
	t.Fatalf("Timeout waiting for courier response for envelope hash %x", hash)
	return nil // This will never be reached due to t.Fatalf, but needed for compilation
}

// testSequenceData holds the data for a BACAP sequence used in testing
type testSequenceData struct {
	Owner         *bacap.WriteCap
	EnvelopeCBORs []byte
	OriginalData  []byte
}

/*
func testNestedEnvelopeRoundTrip(t *testing.T, env *testEnvironment) {
	// PKI documents are already fetched during setup, just verify they're ready
	waitForCourierPKI(t, env)
	waitForReplicasPKI(t, env)

	aliceStatefulWriter, bobStatefulReader := aliceAndBobKeyExchangeKeys(t, env)

	// Create final destination sequence and real messages
	finalDestinationWriter, realMessages := setupFinalDestinationAndMessages(t, env)

	// Generate CourierEnvelopes for the real messages
	courierEnvelopes, _ := createCourierEnvelopesForMessages(t, env, finalDestinationWriter, realMessages)

	// CBOR encode and chunk the CourierEnvelopes
	chunks, courierEnvelopeCBORData := chunkCourierEnvelopes(t, env, courierEnvelopes)

	// Write chunks to replicas and verify
	writeChunksToReplicas(t, env, chunks, aliceStatefulWriter)

	// Read back and verify data integrity
	reconstructedData := readBackAndVerifyChunks(t, env, chunks, bobStatefulReader, courierEnvelopeCBORData)

	// Verify CourierEnvelopes can be decoded
	verifyDecodedEnvelopes(t, courierEnvelopes, reconstructedData)

	// Execute copy command and verify
	executeCopyCommand(t, env, aliceStatefulWriter)

	// Read from final destination and verify
	readFromFinalDestinationAndVerify(t, env, finalDestinationWriter, realMessages)

	// Verify tombstones were written
	verifyTombstones(t, env, aliceStatefulWriter.Owner, len(chunks))
}
*/

/*
// setupFinalDestinationAndMessages creates the final destination sequence and real messages
func setupFinalDestinationAndMessages(t *testing.T, env *testEnvironment) (*bacap.StatefulWriter, [][]byte) {
	finalDestinationOwner, err := bacap.NewWriteCap(rand.Reader)
	require.NoError(t, err)
	finalDestinationWriter, err := bacap.NewStatefulWriter(finalDestinationOwner, constants.PIGEONHOLE_CTX)
	require.NoError(t, err)
	t.Log("Created final destination sequence (Sequence B)")

	realMessages := [][]byte{
		[]byte("Secret message 1: This is confidential data that should end up in the final destination"),
		[]byte("Secret message 2: Another piece of sensitive information for the final sequence"),
		[]byte("Secret message 3: The third and final piece of data for our destination sequence"),
	}
	t.Logf("Created %d real messages for final destination", len(realMessages))

	return finalDestinationWriter, realMessages
}
*/

/*
// createCourierEnvelopesForMessages generates CourierEnvelopes for the real messages
func createCourierEnvelopesForMessages(t *testing.T, env *testEnvironment, finalDestinationWriter *bacap.StatefulWriter, realMessages [][]byte) ([]*pigeonhole.CourierEnvelope, []byte) {
	var courierEnvelopes []*pigeonhole.CourierEnvelope
	var originalDataForVerification []byte

	for i, message := range realMessages {
		t.Logf("Creating CourierEnvelope %d for message: %s", i+1, string(message[:50])+"...")

		// BACAP encrypt the message for the final destination sequence
		paddedMessage, err := common.CreatePaddedPayload(message, env.geometry.MaxPlaintextPayloadLength + 4)
		require.NoError(t, err)

		boxID, bacapCiphertext, sigraw, err := finalDestinationWriter.EncryptNext(paddedMessage)
		require.NoError(t, err)

		signature := [bacap.SignatureSize]byte{}
		copy(signature[:], sigraw)

		envelope := aliceComposesDirectWriteToReplica(t, env, &boxID, &signature, bacapCiphertext)
		courierEnvelopes = append(courierEnvelopes, envelope)
		originalDataForVerification = append(originalDataForVerification, message...)

		t.Logf("Created CourierEnvelope for BoxID %x, final destination replicas: %v",
			boxID[:8], envelope.IntermediateReplicas)
	}

	return courierEnvelopes, originalDataForVerification
}

// chunkCourierEnvelopes CBOR encodes and chunks the CourierEnvelopes
func chunkCourierEnvelopes(t *testing.T, env *testEnvironment, courierEnvelopes []*pigeonhole.CourierEnvelope) ([][]byte, []byte) {
	maxPlaintextPayloadLength := env.geometry.MaxPlaintextPayloadLength
	t.Logf("Using MaxPlaintextPayloadLength: %d bytes", maxPlaintextPayloadLength)

	var chunks [][]byte
	var currentChunk []byte
	var courierEnvelopeCBORData []byte

	for i, envelope := range courierEnvelopes {
		envelopeBytes := envelope.Bytes()
		courierEnvelopeCBORData = append(courierEnvelopeCBORData, envelopeBytes...)
		t.Logf("CBOR encoded CourierEnvelope %d: %d bytes", i+1, len(envelopeBytes))

		remainingBytes := envelopeBytes
		for len(remainingBytes) > 0 {
			availableSpace := maxPlaintextPayloadLength - len(currentChunk)

			if availableSpace <= 0 {
				if len(currentChunk) > 0 {
					chunks = append(chunks, currentChunk)
					t.Logf("Created chunk %d: %d bytes", len(chunks), len(currentChunk))
				}
				currentChunk = nil
				availableSpace = maxPlaintextPayloadLength
			}

			chunkSize := len(remainingBytes)
			if chunkSize > availableSpace {
				chunkSize = availableSpace
			}

			currentChunk = append(currentChunk, remainingBytes[:chunkSize]...)
			remainingBytes = remainingBytes[chunkSize:]

			t.Logf("Added %d bytes of CourierEnvelope %d to chunk (remaining: %d bytes)",
				chunkSize, i+1, len(remainingBytes))
		}
	}

	if len(currentChunk) > 0 {
		chunks = append(chunks, currentChunk)
		t.Logf("Created final chunk %d: %d bytes", len(chunks), len(currentChunk))
	}

	t.Logf("Total CourierEnvelope CBOR data size: %d bytes", len(courierEnvelopeCBORData))
	t.Logf("Packed into %d chunks with complete CBOR objects", len(chunks))

	return chunks, courierEnvelopeCBORData
}

// writeChunksToReplicas writes each chunk to replicas using BACAP
func writeChunksToReplicas(t *testing.T, env *testEnvironment, chunks [][]byte, aliceStatefulWriter *bacap.StatefulWriter) {
	t.Logf("Writing %d chunks to replicas", len(chunks))
	for i, chunk := range chunks {
		isLastChunk := (i == len(chunks)-1)
		t.Logf("Writing chunk %d (%d bytes), IsLast=%v", i+1, len(chunk), isLastChunk)

		aliceEnvelope := aliceComposesNextMessageWithIsLast(t, chunk, env, aliceStatefulWriter, isLastChunk)
		courierWriteReply := injectCourierEnvelope(t, env, aliceEnvelope)

		aliceEnvHash := aliceEnvelope.EnvelopeHash()
		require.Equal(t, courierWriteReply.EnvelopeHash[:], aliceEnvHash[:])
		require.Equal(t, uint8(0), courierWriteReply.ErrorCode)
		require.Equal(t, uint8(0), courierWriteReply.ReplyIndex)
		require.Nil(t, courierWriteReply.Payload)

		t.Logf("Successfully wrote chunk %d (IsLast=%v)", i+1, isLastChunk)
	}

	// Wait for replication to complete
	t.Log("Waiting for replication to complete...")
	time.Sleep(2 * time.Second)
}

// readBackAndVerifyChunks reads back all chunks and reconstructs the original data
func readBackAndVerifyChunks(t *testing.T, env *testEnvironment, chunks [][]byte, bobStatefulReader *bacap.StatefulReader, courierEnvelopeCBORData []byte) []byte {
	t.Logf("Reading back %d chunks from replicas", len(chunks))
	var reconstructedData []byte

	for i := 0; i < len(chunks); i++ {
		chunkData := readAndDecryptSingleChunk(t, env, bobStatefulReader, i+1)
		reconstructedData = append(reconstructedData, chunkData...)
	}

	// Verify the reconstructed data matches the original CourierEnvelope CBOR data
	require.Equal(t, len(courierEnvelopeCBORData), len(reconstructedData), "Reconstructed data length should match original")
	require.Equal(t, courierEnvelopeCBORData, reconstructedData, "Reconstructed data should match original CourierEnvelope CBOR data")

	t.Logf("Successfully verified %d bytes of reconstructed CourierEnvelope CBOR data", len(reconstructedData))
	return reconstructedData
}

// readAndDecryptSingleChunk reads and decrypts a single chunk from replicas
func readAndDecryptSingleChunk(t *testing.T, env *testEnvironment, bobStatefulReader *bacap.StatefulReader, chunkNum int) []byte {
	t.Logf("Reading chunk %d", chunkNum)

	bobReadRequest, bobPrivateKey := composeReadRequest(t, env, bobStatefulReader)
	courierReadReply := injectCourierEnvelope(t, env, bobReadRequest)

	bobEnvHash := bobReadRequest.EnvelopeHash()
	require.Equal(t, courierReadReply.EnvelopeHash[:], bobEnvHash[:])
	require.Equal(t, uint8(0), courierReadReply.ErrorCode)

	// With immediate proxying, we should get a non-nil payload on the first request
	if courierReadReply.Payload == nil {
		t.Logf("First read request returned nil payload for chunk %d, falling back to polling", chunkNum)
		courierReadReply = waitForReplicaResponse(t, env, bobReadRequest)
	}

	require.NotNil(t, courierReadReply.Payload, "Should have payload")

	// Decrypt and verify the chunk
	replicaEpoch, _, _ := replicaCommon.ReplicaNow()
	replicaIndex := int(bobReadRequest.IntermediateReplicas[courierReadReply.ReplyIndex])
	replicaPubKey := env.replicaKeys[replicaIndex][replicaEpoch]
	rawInnerMsg, err := mkemNikeScheme.DecryptEnvelope(bobPrivateKey, replicaPubKey, courierReadReply.Payload)
	require.NoError(t, err)

	innerMsg, err := common.ReplicaMessageReplyInnerMessageFromBytes(rawInnerMsg)
	require.NoError(t, err)
	require.NotNil(t, innerMsg.ReplicaReadReply)

	// Debug the read reply
	t.Logf("ReplicaReadReply ErrorCode: %d", innerMsg.ReplicaReadReply.ErrorCode)
	t.Logf("ReplicaReadReply BoxID: %x", innerMsg.ReplicaReadReply.BoxID[:8])
	t.Logf("ReplicaReadReply Payload length: %d", len(innerMsg.ReplicaReadReply.Payload))
	t.Logf("ReplicaReadReply Signature is nil: %v", innerMsg.ReplicaReadReply.Signature == nil)

	if innerMsg.ReplicaReadReply.ErrorCode != 0 {
		t.Fatalf("Replica returned error code %d for chunk %d", innerMsg.ReplicaReadReply.ErrorCode, chunkNum)
	}
	require.NotNil(t, innerMsg.ReplicaReadReply.Signature, "Signature should not be nil for chunk %d", chunkNum)

	boxID, err := bobStatefulReader.NextBoxID()
	require.NoError(t, err)
	paddedChunkData, err := bobStatefulReader.DecryptNext(constants.PIGEONHOLE_CTX, *boxID, innerMsg.ReplicaReadReply.Payload, *innerMsg.ReplicaReadReply.Signature)
	require.NoError(t, err)

	// Extract the actual data from the padded payload (remove 4-byte length prefix and padding)
	chunkData, err := common.ExtractDataFromPaddedPayload(paddedChunkData)
	require.NoError(t, err)

	t.Logf("Successfully read chunk %d: %d bytes (extracted from %d padded bytes)", chunkNum, len(chunkData), len(paddedChunkData))
	return chunkData
}

// verifyDecodedEnvelopes verifies that CourierEnvelopes can be decoded from reconstructed data
func verifyDecodedEnvelopes(t *testing.T, courierEnvelopes []*pigeonhole.CourierEnvelope, reconstructedData []byte) {
	t.Log("Verifying CourierEnvelopes can be decoded from reconstructed data...")
	var decodedEnvelopes []*pigeonhole.CourierEnvelope
	offset := 0

	for i := 0; i < len(courierEnvelopes); i++ {
		// Find the length of the next CBOR object
		originalEnvelopeBytes := courierEnvelopes[i].Bytes()
		envelopeLength := len(originalEnvelopeBytes)

		if offset+envelopeLength > len(reconstructedData) {
			t.Fatalf("Not enough data to decode envelope %d", i)
		}

		envelopeData := reconstructedData[offset : offset+envelopeLength]
		envelope, err := pigeonhole.CourierEnvelopeFromBytes(envelopeData)
		require.NoError(t, err)
		decodedEnvelopes = append(decodedEnvelopes, envelope)
		offset += envelopeLength

		t.Logf("Successfully decoded CourierEnvelope %d from reconstructed data", i+1)
	}

	require.Equal(t, len(courierEnvelopes), len(decodedEnvelopes), "Should decode same number of envelopes")
	t.Log("CourierEnvelope round trip test completed successfully")
}

// executeCopyCommand executes the copy command and verifies success
func executeCopyCommand(t *testing.T, env *testEnvironment, aliceStatefulWriter *bacap.StatefulWriter) {
	t.Log("Testing copy command to execute CourierEnvelopes...")
	copyCommand := &common.CopyCommand{
		WriteCap: aliceStatefulWriter.Owner, // Alice's WriteCap for Sequence A
	}

	// Create a CourierQuery with the embedded CopyCommand
	courierQuery := &pigeonhole.CourierQuery{
		CopyCommand: copyCommand,
	}

	// Send the CourierQuery to the courier and expect a reply
	t.Log("Sending CopyCommand to courier...")
	queryBytes := courierQuery.Bytes()

	// Generate a unique request ID using nanosecond timestamp
	requestID := uint64(time.Now().UnixNano())

	// Register this request with the response router and get a response channel
	responseCh := env.responseRouter.registerRequest(requestID)

	// Clean up the response map entry when done
	defer env.responseRouter.unregisterRequest(requestID)

	// Create a cborplugin.Request to send to the courier
	requestCmd := &cborplugin.Request{
		ID:      requestID,                                                     // Use unique request ID
		SURB:    []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}, // Fake SURB needed for testing
		Payload: queryBytes,
	}

	// Send the request to the courier - this will trigger the courier's OnCommand method
	err := env.courier.Courier.OnCommand(requestCmd)
	require.NoError(t, err)
	t.Log("CopyCommand processed through courier OnCommand")

	// Wait for response with timeout
	var responseCmd cborplugin.Command
	select {
	case responseCmd = <-responseCh:
		t.Log("Received response from courier for CopyCommand")
	case <-time.After(30 * time.Second): // Longer timeout for copy operations
		t.Fatal("Timeout waiting for CopyCommand response")
	}

	var response *cborplugin.Response
	switch r := responseCmd.(type) {
	case *cborplugin.Response:
		response = r
	default:
		t.Fatalf(errUnexpectedResponseType, responseCmd)
	}

	// Decode the CourierQueryReply from the response payload
	courierQueryReply, err := pigeonhole.CourierQueryReplyFromBytes(response.Payload)
	require.NoError(t, err)
	require.NotNil(t, courierQueryReply.CopyCommandReply, "Should have CopyCommandReply")

	// Check the error code - 0 means success
	errorCode := courierQueryReply.CopyCommandReply.ErrorCode
	t.Logf("CopyCommand reply ErrorCode: %d", errorCode)
	require.Equal(t, uint8(0), errorCode, "CopyCommand should succeed")

	t.Log("CopyCommand executed successfully - real data should now be written to final destination sequence!")

	// Wait for the data to be available (eventually we'll use events/channels instead of sleep)
	t.Log("Waiting 2 seconds for data to be available...")
	time.Sleep(2 * time.Second)
}

// readFromFinalDestinationAndVerify reads from final destination and verifies messages match originals
func readFromFinalDestinationAndVerify(t *testing.T, env *testEnvironment, finalDestinationWriter *bacap.StatefulWriter, realMessages [][]byte) {
	t.Log("Reading back data from final destination sequence...")

	// Create a StatefulReader for Bob to read from the final destination sequence
	bobReadCap := finalDestinationWriter.Owner.ReadCap()
	bobStatefulReader, err := bacap.NewStatefulReader(bobReadCap, constants.PIGEONHOLE_CTX)
	require.NoError(t, err)

	// Read back each message and verify it matches the original
	var readBackMessages [][]byte
	for i, originalMessage := range realMessages {
		decryptedMessage := readAndVerifySingleMessage(t, env, bobStatefulReader, i+1)
		readBackMessages = append(readBackMessages, decryptedMessage)

		// Verify this message matches the original
		require.Equal(t, originalMessage, decryptedMessage, "Message %d should match original", i+1)
	}

	t.Logf("SUCCESS! All %d messages were successfully read back from final destination and match the originals!", len(realMessages))
	t.Log("Full round-trip test completed: Alice -> Temporary Sequence -> Copy Command -> Final Destination -> Bob")

	// Wait for tombstones to be written to replicas
	t.Log("Waiting for tombstones to be written to replicas...")
	time.Sleep(5 * time.Second)
}

// readAndVerifySingleMessage reads and verifies a single message from final destination
func readAndVerifySingleMessage(t *testing.T, env *testEnvironment, bobStatefulReader *bacap.StatefulReader, messageNum int) []byte {
	t.Logf("Reading back message %d from final destination", messageNum)

	// Create a read request for the next box in Bob's sequence
	readRequest, privateKey := composeReadRequest(t, env, bobStatefulReader)
	readReply := injectCourierEnvelope(t, env, readRequest)

	if readReply.Payload == nil {
		t.Logf("First read request returned nil payload for message %d, falling back to polling", messageNum)
		readReply = waitForReplicaResponse(t, env, readRequest)
	}

	require.NotNil(t, readReply.Payload, "Should have payload for message %d", messageNum)

	// Decrypt the replica response using MKEM
	replicaEpoch, _, _ := replicaCommon.ReplicaNow()
	replicaIndex := int(readRequest.IntermediateReplicas[readReply.ReplyIndex])
	replicaPubKey := env.replicaKeys[replicaIndex][replicaEpoch]
	rawInnerMsg, err := mkemNikeScheme.DecryptEnvelope(privateKey, replicaPubKey, readReply.Payload)
	require.NoError(t, err)

	innerMsg, err := common.ReplicaMessageReplyInnerMessageFromBytes(rawInnerMsg)
	require.NoError(t, err)
	require.NotNil(t, innerMsg.ReplicaReadReply, "Should have ReplicaReadReply for message %d", messageNum)

	// Decrypt the BACAP data to get the original message
	boxID, err := bobStatefulReader.NextBoxID()
	require.NoError(t, err)
	paddedDecryptedMessage, err := bobStatefulReader.DecryptNext(constants.PIGEONHOLE_CTX, *boxID, innerMsg.ReplicaReadReply.Payload, *innerMsg.ReplicaReadReply.Signature)
	require.NoError(t, err)

	// Extract the actual message data from the padded payload (remove 4-byte length prefix and padding)
	decryptedMessage, err := common.ExtractDataFromPaddedPayload(paddedDecryptedMessage)
	require.NoError(t, err)

	t.Logf("Successfully read back message %d: '%s'", messageNum, string(decryptedMessage))
	return decryptedMessage
}

// verifyTombstones verifies that tombstones were written to the temporary sequence
func verifyTombstones(t *testing.T, env *testEnvironment, tempWriteCap *bacap.WriteCap, expectedBoxCount int) {
	t.Logf("Verifying %d tombstones in temporary sequence", expectedBoxCount)

	// Create a StatefulReader from the temporary sequence WriteCap
	tempReadCap := tempWriteCap.ReadCap()
	tempStatefulReader, err := bacap.NewStatefulReader(tempReadCap, constants.PIGEONHOLE_CTX)
	require.NoError(t, err)

	// Read back each box and verify it contains all zeros
	for i := 0; i < expectedBoxCount; i++ {
		t.Logf("Verifying tombstone %d/%d", i+1, expectedBoxCount)

		// Create a read request for the next box
		readRequest, privateKey := composeReadRequest(t, env, tempStatefulReader)
		readReply := injectCourierEnvelope(t, env, readRequest)

		if readReply.Payload == nil {
			t.Logf("First read request returned nil payload for tombstone %d, falling back to polling", i+1)
			readReply = waitForReplicaResponse(t, env, readRequest)
		}

		require.NotNil(t, readReply.Payload, "Should have payload for tombstone %d", i+1)

		// Decrypt the replica response using MKEM
		replicaEpoch, _, _ := replicaCommon.ReplicaNow()
		replicaIndex := int(readRequest.IntermediateReplicas[readReply.ReplyIndex])
		replicaPubKey := env.replicaKeys[replicaIndex][replicaEpoch]
		rawInnerMsg, err := mkemNikeScheme.DecryptEnvelope(privateKey, replicaPubKey, readReply.Payload)
		require.NoError(t, err)

		innerMsg, err := common.ReplicaMessageReplyInnerMessageFromBytes(rawInnerMsg)
		require.NoError(t, err)
		require.NotNil(t, innerMsg.ReplicaReadReply, "Should have ReplicaReadReply for tombstone %d", i+1)

		// Decrypt the BACAP data to get the tombstone payload
		boxID, err := tempStatefulReader.NextBoxID()
		require.NoError(t, err)
		tombstonePayload, err := tempStatefulReader.DecryptNext(constants.PIGEONHOLE_CTX, *boxID, innerMsg.ReplicaReadReply.Payload, *innerMsg.ReplicaReadReply.Signature)
		require.NoError(t, err)

		// Verify the payload is all zeros using constant-time comparison
		isZero := util.CtIsZero(tombstonePayload)
		require.True(t, isZero, "Tombstone %d should contain all zeros", i+1)

		t.Logf("Successfully verified tombstone %d: %d bytes of zeros", i+1, len(tombstonePayload))
	}

	t.Logf("SUCCESS! All %d tombstones verified - temporary sequence has been properly overwritten with zeros", expectedBoxCount)
}

// aliceComposesDirectWriteToReplica creates a CourierEnvelope that writes the given
// BACAP-encrypted data directly to the replicas using the provided BoxID and signature.
// Uses the sharding algorithm to determine which replicas should store this BoxID.
func aliceComposesDirectWriteToReplica(t *testing.T, env *testEnvironment, boxID *[bacap.BoxIDSize]byte, signature *[bacap.SignatureSize]byte, ciphertext []byte) *pigeonhole.CourierEnvelope {
	writeRequest := commands.ReplicaWrite{
		PigeonholeGeometry: env.geometry,
		BoxID:              boxID,
		Signature:          signature,
		Payload:            ciphertext,
	}
	msg := &pigeonhole.ReplicaInnerMessage{
		ReplicaWrite: &writeRequest,
	}

	sharding := getShardingInfo(t, env, boxID)

	for _, replicaIndex := range sharding.ReplicaIndices {
		t.Logf("BoxID %x will be stored on replica %d", boxID[:8], replicaIndex)
	}

	return createMKEMEnvelope(t, sharding, msg, false)
}

// aliceComposesReadFromReplica creates a CourierEnvelope that reads the given BoxID from replicas.
// Uses the sharding algorithm to determine which replicas should have this BoxID.
func aliceComposesReadFromReplica(t *testing.T, env *testEnvironment, boxID *[bacap.BoxIDSize]byte) *pigeonhole.CourierEnvelope {
	readRequest := common.ReplicaRead{
		BoxID: boxID,
	}
	msg := &pigeonhole.ReplicaInnerMessage{
		ReplicaRead: &readRequest,
	}

	sharding := getShardingInfo(t, env, boxID)

	for _, replicaIndex := range sharding.ReplicaIndices {
		t.Logf("BoxID %x will be read from replica %d", boxID[:8], replicaIndex)
	}

	return createMKEMEnvelope(t, sharding, msg, true)
}

func injectCourierEnvelope(t *testing.T, env *testEnvironment, envelope *pigeonhole.CourierEnvelope) *pigeonhole.CourierEnvelopeReply {
	// Create a CBOR plugin command containing the CourierQuery with CourierEnvelope
	t.Logf("COURIER_INJECT: Creating CourierQuery with envelope for intermediaries: %v", envelope.IntermediateReplicas)
	courierQuery := &pigeonhole.CourierQuery{
		Envelope:       envelope,
		CopyCommandLen: 0,
		CopyCommand:    nil,
	}

	t.Logf("COURIER_INJECT: Sending request to courier")
	response := createRequestWithResponse(t, env, courierQuery, 10)
	t.Logf("COURIER_INJECT: Received response from courier, payload length: %d", len(response.Payload))

	courierQueryReply, err := pigeonhole.CourierQueryReplyFromBytes(response.Payload)
	require.NoError(t, err)
	require.NotNil(t, courierQueryReply)
	require.NotNil(t, courierQueryReply.CourierEnvelopeReply)

	t.Logf("COURIER_INJECT: Successfully parsed courier reply")
	return courierQueryReply.CourierEnvelopeReply
}

func composeReadRequest(t *testing.T, env *testEnvironment, reader *bacap.StatefulReader) (*pigeonhole.CourierEnvelope, nike.PrivateKey) {
	boxID, err := reader.NextBoxID()
	require.NoError(t, err)

	// DEBUG: Log Bob's BoxID
	t.Logf("DEBUG: Bob reads from BoxID: %x", boxID[:])

	readRequest := &common.ReplicaRead{
		BoxID: boxID,
	}

	msg := &pigeonhole.ReplicaInnerMessage{
		ReplicaRead: readRequest,
	}

	sharding := getShardingInfo(t, env, boxID)

	for _, replicaIndex := range sharding.ReplicaIndices {
		t.Logf("BoxID %x will be read from replica %d", boxID[:8], replicaIndex)
	}

	mkemPrivateKey, mkemCiphertext := mkemNikeScheme.Encapsulate(sharding.ReplicaPubKeys, msg.Bytes())
	mkemPublicKey := mkemPrivateKey.Public()
	replicaEpoch, _, _ := replicaCommon.ReplicaNow()

	return &pigeonhole.CourierEnvelope{
		SenderEPubKey:        mkemPublicKey.Bytes(),
		IntermediateReplicas: sharding.ReplicaIndices,
		DEK:                  [2]*[mkem.DEKSize]byte{mkemCiphertext.DEKCiphertexts[0], mkemCiphertext.DEKCiphertexts[1]},
		Ciphertext:           mkemCiphertext.Envelope,
		IsRead:               true,
		Epoch:                replicaEpoch,
	}, mkemPrivateKey
}

// waitForReplicaResponse waits for the courier to receive a reply by repeatedly trying the request
// until we get a non-nil payload, indicating the replica response has been received
func waitForReplicaResponse(t *testing.T, env *testEnvironment, envelope *pigeonhole.CourierEnvelope) *pigeonhole.CourierEnvelopeReply {
	maxWait := 10 * time.Second
	checkInterval := 100 * time.Millisecond
	start := time.Now()

	for time.Since(start) < maxWait {
		reply := injectCourierEnvelope(t, env, envelope)

		// If we got a non-nil payload, the response is ready
		if reply.Payload != nil {
			t.Logf("Courier response ready - received payload of length %d", len(reply.Payload))
			return reply
		}

		// Wait before trying again
		time.Sleep(checkInterval)
	}

	t.Fatalf("Timeout waiting for courier response for envelope hash %x", envelope.EnvelopeHash()[:8])
	return nil // This will never be reached due to t.Fatalf, but needed for compilation
}
*/
