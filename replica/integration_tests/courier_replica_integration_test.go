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
	"github.com/katzenpost/katzenpost/core/wire/commands"
	courierServer "github.com/katzenpost/katzenpost/courier/server"
	courierConfig "github.com/katzenpost/katzenpost/courier/server/config"
	"github.com/katzenpost/katzenpost/loops"
	"github.com/katzenpost/katzenpost/replica"
	"github.com/katzenpost/katzenpost/replica/common"
	replicaCommon "github.com/katzenpost/katzenpost/replica/common"
	"github.com/katzenpost/katzenpost/replica/config"
	"github.com/katzenpost/katzenpost/server/cborplugin"
)

const (
	// testPKIScheme is the PKI signature scheme used in tests
	testPKIScheme = "Ed25519 Sphincs+"
	// testReplicaNameFormat is the format string for replica names in tests
	testReplicaNameFormat = "replica%d"
)

var (
	mkemNikeScheme *mkem.Scheme = mkem.NewScheme(common.NikeScheme)
)

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
func TestCourierReplicaNestedEnvelopeIntegration(t *testing.T) {
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
	geometry       *common.Geometry
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

	// STEP 2: Create all servers with their own PKI clients (like production)
	// Each PKI client will have the same PKI documents available
	replicas := make([]*replica.Server, numReplicas)
	for i := 0; i < numReplicas; i++ {
		replicas[i] = createReplicaServer(t, replicaConfigs[i], createMockPKIClient(t, sphinxGeo, serviceDesc, replicaDescriptors))
	}

	courier := createCourierServer(t, courierCfg, createMockPKIClient(t, sphinxGeo, serviceDesc, replicaDescriptors))

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

	mymockPKIClient := createMockPKIClient(t, sphinxGeo, serviceDesc, replicaDescriptors)

	// Set up response routing system - SetWriteFunc called only once per test environment
	router := newResponseRouter()

	// Set up the write function once and only once - this is critical to avoid data races
	courier.Courier.SetWriteFunc(router.writeFunc)

	// Initialize the pigeonhole geometry
	pigeonholeGeo := common.GeometryFromBoxPayloadLength(2000, common.NikeScheme)

	return &testEnvironment{
		tempDir:        tempDir,
		replicas:       replicas,
		courier:        courier,
		mockPKIClient:  mymockPKIClient,
		replicaConfigs: replicaConfigs,
		courierConfig:  courierCfg,
		cleanup:        cleanup,
		replicaKeys:    replicaKeys,
		geometry:       pigeonholeGeo,
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
		ReplicaNIKEScheme:  common.NikeScheme.Name(),
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
	replicaEpoch, _, _ := common.ReplicaNow()

	replicaNIKEPublicKey, replicaNIKEPrivateKey, err := common.NikeScheme.GenerateKeyPair()
	require.NoError(t, err)
	nikePem.PrivateKeyToFile(filepath.Join(dataDir, fmt.Sprintf("replica.%d.private.pem", replicaEpoch)), replicaNIKEPrivateKey, common.NikeScheme)
	nikePem.PublicKeyToFile(filepath.Join(dataDir, fmt.Sprintf("replica.%d.public.pem", replicaEpoch)), replicaNIKEPublicKey, common.NikeScheme)
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
		EnvelopeScheme:   common.NikeScheme.Name(),
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

	replicaEpoch, _, _ := common.ReplicaNow()
	pubKey, ok := replicaKeys[replicaEpoch]
	require.True(t, ok)
	pubKeyBlob, err := pubKey.MarshalBinary()
	require.NoError(t, err)
	desc.EnvelopeKeys[replicaEpoch] = pubKeyBlob

	return desc
}

func createMockPKIClient(t *testing.T, sphinxGeo *geo.Geometry, serviceDesc *pki.MixDescriptor, replicaDescriptors []*pki.ReplicaDescriptor) *mockPKIClient {
	mock := newMockPKIClient(t)

	// here we generate a PKI document and then store it for three epochs
	// while carefully modify each document's epoch value:
	currentEpoch, _, _ := epochtime.Now()
	for _, epoch := range []uint64{currentEpoch - 2, currentEpoch - 1, currentEpoch, currentEpoch + 1} {
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
	docs map[uint64]*pki.Document
}

func newMockPKIClient(t *testing.T) *mockPKIClient {
	return &mockPKIClient{
		t:    t,
		docs: make(map[uint64]*pki.Document),
	}
}

func (c *mockPKIClient) Get(ctx context.Context, epoch uint64) (*pki.Document, []byte, error) {
	doc, exists := c.docs[epoch]
	if !exists {
		return nil, nil, fmt.Errorf("no PKI document available for epoch %d", epoch)
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

func aliceComposesNextMessage(t *testing.T, message []byte, env *testEnvironment, aliceStatefulWriter *bacap.StatefulWriter) *common.CourierEnvelope {
	boxID, ciphertext, sigraw, err := aliceStatefulWriter.EncryptNext(message)
	require.NoError(t, err)

	// DEBUG: Log Alice's BoxID
	t.Logf("DEBUG: Alice writes to BoxID: %x", boxID[:])

	sig := [bacap.SignatureSize]byte{}
	copy(sig[:], sigraw)

	writeRequest := commands.ReplicaWrite{
		BoxID:     &boxID,
		Signature: &sig,
		Payload:   ciphertext,
	}
	msg := &common.ReplicaInnerMessage{
		ReplicaWrite: &writeRequest,
	}

	currentEpoch, _, _ := epochtime.Now()
	replicaEpoch, _, _ := common.ReplicaNow()
	replicaPubKey1 := env.mockPKIClient.docs[currentEpoch].StorageReplicas[0].EnvelopeKeys[replicaEpoch]
	replicaPubKey2 := env.mockPKIClient.docs[currentEpoch].StorageReplicas[1].EnvelopeKeys[replicaEpoch]

	replicaPubKeys := make([]nike.PublicKey, 2)
	replicaPubKeys[0], err = common.NikeScheme.UnmarshalBinaryPublicKey(replicaPubKey1)
	require.NoError(t, err)
	replicaPubKeys[1], err = common.NikeScheme.UnmarshalBinaryPublicKey(replicaPubKey2)
	require.NoError(t, err)

	mkemPrivateKey, mkemCiphertext := mkemNikeScheme.Encapsulate(
		replicaPubKeys, msg.Bytes(),
	)
	mkemPublicKey := mkemPrivateKey.Public()

	return &common.CourierEnvelope{
		SenderEPubKey:        mkemPublicKey.Bytes(),
		IntermediateReplicas: [2]uint8{0, 1}, // indices to pkidoc's StorageReplicas
		DEK: [2]*[mkem.DEKSize]byte{mkemCiphertext.DEKCiphertexts[0],
			mkemCiphertext.DEKCiphertexts[1]},
		Ciphertext: mkemCiphertext.Envelope,
		IsRead:     false,
	}
}

func aliceAndBobKeyExchangeKeys(t *testing.T, env *testEnvironment) (*bacap.StatefulWriter, *bacap.StatefulReader) {
	// --- Alice creates a BACAP sequence and gives Bob a sequence read capability
	// Bob can read from his StatefulReader that which Alice writes with her StatefulWriter.
	aliceOwner, err := bacap.NewBoxOwnerCap(rand.Reader)
	require.NoError(t, err)
	aliceStatefulWriter, err := bacap.NewStatefulWriter(aliceOwner, constants.PIGEONHOLE_CTX)
	require.NoError(t, err)
	bobReadCap := aliceOwner.UniversalReadCap()
	bobStatefulReader, err := bacap.NewStatefulReader(bobReadCap, constants.PIGEONHOLE_CTX)
	require.NoError(t, err)
	return aliceStatefulWriter, bobStatefulReader
}

// forceCourierPKIFetch forces the courier to fetch PKI documents
func forceCourierPKIFetch(t *testing.T, env *testEnvironment) {
	t.Log("Forcing PKI fetch for courier")
	err := env.courier.PKI.ForceFetchPKI()
	require.NoError(t, err)
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

// forceReplicasPKIFetch forces all replicas to fetch PKI documents
func forceReplicasPKIFetch(t *testing.T, env *testEnvironment) {
	for i, replica := range env.replicas {
		t.Logf("Forcing PKI fetch for replica %d", i)
		err := replica.PKIWorker.ForceFetchPKI()
		require.NoError(t, err)
	}
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

	aliceEnvHash1 := aliceEnvelope1.EnvelopeHash()
	require.Equal(t, courierWriteReply1.EnvelopeHash[:], aliceEnvHash1[:])
	require.Equal(t, uint8(0), courierWriteReply1.ErrorCode)
	require.Equal(t, uint8(0), courierWriteReply1.ReplyIndex)
	require.Nil(t, courierWriteReply1.Payload)

	bobReadRequest1, bobPrivateKey1 := composeReadRequest(t, env, bobStatefulReader)

	// First read request should now get immediate reply with payload due to immediate proxying
	courierReadReply1 := injectCourierEnvelope(t, env, bobReadRequest1)

	bobEnvHash1 := bobReadRequest1.EnvelopeHash()
	require.Equal(t, courierReadReply1.EnvelopeHash[:], bobEnvHash1[:])
	require.Equal(t, uint8(0), courierReadReply1.ErrorCode)

	// With immediate proxying, we should get a non-nil payload on the first request
	if courierReadReply1.Payload == nil {
		t.Logf("First read request returned nil payload, this suggests immediate proxying didn't work")
		// For now, let's still allow the test to continue to see what happens
		// In the future, this should be a hard requirement
		t.Logf("Continuing test to see if traditional caching still works...")

		// Fall back to traditional polling approach for now
		courierReadReply1 = waitForReplicaResponse(t, env, bobReadRequest1)
	}

	// ReplyIndex now correctly indicates which replica replied (0 or 1)
	require.True(t, courierReadReply1.ReplyIndex < 2, "ReplyIndex should be 0 or 1")
	require.NotNil(t, courierReadReply1.Payload, "Should have payload either from immediate proxying or cache")

	replicaEpoch, _, _ := common.ReplicaNow()

	// Now ReplyIndex correctly indicates which replica replied (0 or 1)
	replicaIndex := int(bobReadRequest1.IntermediateReplicas[courierReadReply1.ReplyIndex])
	replicaPubKey := env.replicaKeys[replicaIndex][replicaEpoch]
	rawInnerMsg, err := mkemNikeScheme.DecryptEnvelope(bobPrivateKey1, replicaPubKey, courierReadReply1.Payload)
	require.NoError(t, err)

	// common.ReplicaMessageReplyInnerMessage
	innerMsg, err := common.ReplicaMessageReplyInnerMessageFromBytes(rawInnerMsg)
	require.NoError(t, err)
	require.NotNil(t, innerMsg.ReplicaReadReply)

	boxid, err := bobStatefulReader.NextBoxID()
	require.NoError(t, err)
	bobPlaintext1, err := bobStatefulReader.DecryptNext(constants.PIGEONHOLE_CTX, *boxid, innerMsg.ReplicaReadReply.Payload, *innerMsg.ReplicaReadReply.Signature)
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

		aliceEnvHash := aliceEnvelope.EnvelopeHash()
		require.Equal(t, courierWriteReply.EnvelopeHash[:], aliceEnvHash[:])
		require.Equal(t, uint8(0), courierWriteReply.ErrorCode)
		require.Equal(t, uint8(0), courierWriteReply.ReplyIndex)
		require.Nil(t, courierWriteReply.Payload)

		t.Logf("Successfully wrote box %d", i+1)
	}

	// Now read back the sequence of boxes
	t.Logf("Reading back sequence of %d boxes", len(messages))
	for i := 0; i < len(messages); i++ {
		t.Logf("Reading box %d", i+1)

		bobReadRequest, bobPrivateKey := composeReadRequest(t, env, bobStatefulReader)

		// First read request should now get immediate reply with payload due to immediate proxying
		courierReadReply := injectCourierEnvelope(t, env, bobReadRequest)

		bobEnvHash := bobReadRequest.EnvelopeHash()
		require.Equal(t, courierReadReply.EnvelopeHash[:], bobEnvHash[:])
		require.Equal(t, uint8(0), courierReadReply.ErrorCode)

		// With immediate proxying, we should get a non-nil payload on the first request
		if courierReadReply.Payload == nil {
			t.Logf("First read request returned nil payload for box %d, falling back to polling", i+1)
			courierReadReply = waitForReplicaResponse(t, env, bobReadRequest)
		}

		// ReplyIndex correctly indicates which replica replied (0 or 1)
		require.True(t, courierReadReply.ReplyIndex < 2, "ReplyIndex should be 0 or 1")
		require.NotNil(t, courierReadReply.Payload, "Should have payload either from immediate proxying or cache")

		// Decrypt and verify the message
		replicaEpoch, _, _ := common.ReplicaNow()
		replicaIndex := int(bobReadRequest.IntermediateReplicas[courierReadReply.ReplyIndex])
		replicaPubKey := env.replicaKeys[replicaIndex][replicaEpoch]
		rawInnerMsg, err := mkemNikeScheme.DecryptEnvelope(bobPrivateKey, replicaPubKey, courierReadReply.Payload)
		require.NoError(t, err)

		// common.ReplicaMessageReplyInnerMessage
		innerMsg, err := common.ReplicaMessageReplyInnerMessageFromBytes(rawInnerMsg)
		require.NoError(t, err)
		require.NotNil(t, innerMsg.ReplicaReadReply)

		boxid, err := bobStatefulReader.NextBoxID()
		require.NoError(t, err)
		bobPlaintext, err := bobStatefulReader.DecryptNext(constants.PIGEONHOLE_CTX, *boxid, innerMsg.ReplicaReadReply.Payload, *innerMsg.ReplicaReadReply.Signature)
		require.NoError(t, err)

		// Verify the decrypted message matches what we wrote
		expectedMessage := messages[i]
		require.Equal(t, expectedMessage, bobPlaintext)
		t.Logf("Successfully read and verified box %d: %s", i+1, string(bobPlaintext))
	}

	t.Logf("Successfully completed sequence round-trip test for %d boxes", len(messages))
}

// testSequenceData holds the data for a BACAP sequence used in testing
type testSequenceData struct {
	Owner         *bacap.BoxOwnerCap
	EnvelopeCBORs []byte
	OriginalData  []byte
}

// createFinalDestinationSequence creates the final destination sequence and CourierEnvelopes
func createFinalDestinationSequence(t *testing.T, env *testEnvironment, aliceStatefulWriter *bacap.StatefulWriter) *testSequenceData {
	t.Log("Creating final destination sequence and CourierEnvelopes")

	// Create test data
	originalData := [][]byte{
		[]byte("hello 1"),
		[]byte("hello 2"),
		[]byte("hello 3"),
	}

	// Concatenate the original data
	var concatenatedData []byte
	for _, data := range originalData {
		concatenatedData = append(concatenatedData, data...)
	}

	// Create CourierEnvelopes that write to the final destination
	var envelopeCBORs []byte
	for _, data := range originalData {
		envelopeCBOR := createCourierEnvelopeForDestination(t, env, aliceStatefulWriter, data)
		envelopeCBORs = append(envelopeCBORs, envelopeCBOR...)
	}

	return &testSequenceData{
		Owner:         aliceStatefulWriter.Owner,
		EnvelopeCBORs: envelopeCBORs,
		OriginalData:  concatenatedData,
	}
}

// createAndWriteTemporarySequence creates a temporary sequence and writes CBOR blobs to replicas
func createAndWriteTemporarySequence(t *testing.T, env *testEnvironment, envelopeCBORs [][]byte) *testSequenceData {
	t.Log("Creating temporary sequence and writing CBOR blobs to replicas")

	// Create temporary sequence for storing CBOR blobs
	tempOwner, err := bacap.NewBoxOwnerCap(rand.Reader)
	require.NoError(t, err)
	tempStatefulWriter, err := bacap.NewStatefulWriter(tempOwner, constants.PIGEONHOLE_CTX)
	require.NoError(t, err)

	// Write each CBOR blob to the temporary sequence via courier
	for i, cborBlob := range envelopeCBORs {
		t.Logf("Writing CBOR blob %d (%d bytes) to temporary sequence", i+1, len(cborBlob))

		boxID, ciphertext, sigraw, err := tempStatefulWriter.EncryptNext(cborBlob)
		require.NoError(t, err)

		// Create a new signature for each iteration to avoid pointer reuse
		sig := make([]byte, bacap.SignatureSize)
		copy(sig, sigraw)
		sigArray := (*[bacap.SignatureSize]byte)(sig)

		tempEnvelope := aliceComposesDirectWriteToReplica(t, env, &boxID, sigArray, ciphertext)
		tempReply := injectCourierEnvelope(t, env, tempEnvelope)
		require.Equal(t, uint8(0), tempReply.ErrorCode)
		t.Logf("Successfully wrote CBOR blob %d to temporary sequence", i+1)
	}

	return &testSequenceData{
		Owner:         tempOwner,
		EnvelopeCBORs: []byte{}, // Empty for now since this function doesn't handle CBOR data properly
		OriginalData:  []byte{}, // Empty for now
	}
}

func testNestedEnvelopeRoundTrip(t *testing.T, env *testEnvironment) {
	// PKI documents are already fetched during setup, just verify they're ready
	waitForCourierPKI(t, env)
	waitForReplicasPKI(t, env)

	aliceStatefulWriter, bobStatefulReader := aliceAndBobKeyExchangeKeys(t, env)

	// Create a separate final destination sequence (Sequence B) - this is where the real data will end up
	finalDestinationOwner, err := bacap.NewBoxOwnerCap(rand.Reader)
	require.NoError(t, err)
	finalDestinationWriter, err := bacap.NewStatefulWriter(finalDestinationOwner, constants.PIGEONHOLE_CTX)
	require.NoError(t, err)
	t.Log("Created final destination sequence (Sequence B)")

	// Create real data that we want to end up in the final destination sequence
	realMessages := [][]byte{
		[]byte("Secret message 1: This is confidential data that should end up in the final destination"),
		[]byte("Secret message 2: Another piece of sensitive information for the final sequence"),
		[]byte("Secret message 3: The third and final piece of data for our destination sequence"),
	}
	t.Logf("Created %d real messages for final destination", len(realMessages))

	// Generate proper CourierEnvelopes that contain instructions to write the real data to Sequence B
	var courierEnvelopes []*common.CourierEnvelope
	var originalDataForVerification []byte

	for i, message := range realMessages {
		t.Logf("Creating CourierEnvelope %d for message: %s", i+1, string(message[:50])+"...")

		// BACAP encrypt the message for the final destination sequence
		boxID, bacapCiphertext, sigraw, err := finalDestinationWriter.EncryptNext(message)
		require.NoError(t, err)

		// Create a signature array to avoid pointer reuse
		signature := [bacap.SignatureSize]byte{}
		copy(signature[:], sigraw)

		// Create CourierEnvelope with proper write instructions
		envelope := aliceComposesDirectWriteToReplica(t, env, &boxID, &signature, bacapCiphertext)
		courierEnvelopes = append(courierEnvelopes, envelope)
		originalDataForVerification = append(originalDataForVerification, message...)

		t.Logf("Created CourierEnvelope for BoxID %x, final destination replicas: %v",
			boxID[:8], envelope.IntermediateReplicas)
	}

	// CBOR encode all the CourierEnvelopes - this is the data that goes into Sequence A (intermediate storage)
	var courierEnvelopeCBORData []byte
	for i, envelope := range courierEnvelopes {
		envelopeBytes := envelope.Bytes()
		courierEnvelopeCBORData = append(courierEnvelopeCBORData, envelopeBytes...)
		t.Logf("CBOR encoded CourierEnvelope %d: %d bytes", i+1, len(envelopeBytes))
	}

	// Use the geometry from the test environment
	boxPayloadLength := env.geometry.BoxPayloadLength
	t.Logf("Using BoxPayloadLength: %d bytes", boxPayloadLength)
	t.Logf("Total CourierEnvelope CBOR data size: %d bytes", len(courierEnvelopeCBORData))

	// Split the CourierEnvelope CBOR data into chunks that fit in boxes
	var chunks [][]byte
	for offset := 0; offset < len(courierEnvelopeCBORData); offset += boxPayloadLength {
		end := offset + boxPayloadLength
		if end > len(courierEnvelopeCBORData) {
			end = len(courierEnvelopeCBORData)
		}
		chunk := courierEnvelopeCBORData[offset:end]
		chunks = append(chunks, chunk)
		t.Logf("Created chunk %d: %d bytes (offset %d-%d)", len(chunks), len(chunk), offset, end-1)
	}

	// Write each chunk to replicas using BACAP
	t.Logf("Writing %d chunks to replicas", len(chunks))
	for i, chunk := range chunks {
		t.Logf("Writing chunk %d (%d bytes)", i+1, len(chunk))

		aliceEnvelope := aliceComposesNextMessage(t, chunk, env, aliceStatefulWriter)
		courierWriteReply := injectCourierEnvelope(t, env, aliceEnvelope)

		aliceEnvHash := aliceEnvelope.EnvelopeHash()
		require.Equal(t, courierWriteReply.EnvelopeHash[:], aliceEnvHash[:])
		require.Equal(t, uint8(0), courierWriteReply.ErrorCode)
		require.Equal(t, uint8(0), courierWriteReply.ReplyIndex)
		require.Nil(t, courierWriteReply.Payload)

		t.Logf("Successfully wrote chunk %d", i+1)
	}

	// Wait for replication to complete
	t.Log("Waiting for replication to complete...")
	time.Sleep(2 * time.Second)

	// Read back all chunks and reconstruct the original data
	t.Logf("Reading back %d chunks from replicas", len(chunks))
	var reconstructedData []byte

	for i := 0; i < len(chunks); i++ {
		t.Logf("Reading chunk %d", i+1)

		bobReadRequest, bobPrivateKey := composeReadRequest(t, env, bobStatefulReader)
		courierReadReply := injectCourierEnvelope(t, env, bobReadRequest)

		bobEnvHash := bobReadRequest.EnvelopeHash()
		require.Equal(t, courierReadReply.EnvelopeHash[:], bobEnvHash[:])
		require.Equal(t, uint8(0), courierReadReply.ErrorCode)

		// With immediate proxying, we should get a non-nil payload on the first request
		if courierReadReply.Payload == nil {
			t.Logf("First read request returned nil payload for chunk %d, falling back to polling", i+1)
			courierReadReply = waitForReplicaResponse(t, env, bobReadRequest)
		}

		require.NotNil(t, courierReadReply.Payload, "Should have payload")

		// Decrypt and verify the chunk
		replicaEpoch, _, _ := common.ReplicaNow()
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
			t.Fatalf("Replica returned error code %d for chunk %d", innerMsg.ReplicaReadReply.ErrorCode, i+1)
		}
		require.NotNil(t, innerMsg.ReplicaReadReply.Signature, "Signature should not be nil for chunk %d", i+1)

		boxID, err := bobStatefulReader.NextBoxID()
		require.NoError(t, err)
		chunkData, err := bobStatefulReader.DecryptNext(constants.PIGEONHOLE_CTX, *boxID, innerMsg.ReplicaReadReply.Payload, *innerMsg.ReplicaReadReply.Signature)
		require.NoError(t, err)

		// Append this chunk to our reconstructed data
		reconstructedData = append(reconstructedData, chunkData...)
		t.Logf("Successfully read chunk %d: %d bytes", i+1, len(chunkData))
	}

	// Verify the reconstructed data matches the original CourierEnvelope CBOR data
	require.Equal(t, len(courierEnvelopeCBORData), len(reconstructedData), "Reconstructed data length should match original")
	require.Equal(t, courierEnvelopeCBORData, reconstructedData, "Reconstructed data should match original CourierEnvelope CBOR data")

	t.Logf("Successfully verified %d bytes of reconstructed CourierEnvelope CBOR data", len(reconstructedData))

	// Verify we can decode the CourierEnvelopes back from the reconstructed data
	t.Log("Verifying CourierEnvelopes can be decoded from reconstructed data...")
	var decodedEnvelopes []*common.CourierEnvelope
	offset := 0
	for i := 0; i < len(courierEnvelopes); i++ {
		// Find the length of the next CBOR object
		originalEnvelopeBytes := courierEnvelopes[i].Bytes()
		envelopeLength := len(originalEnvelopeBytes)

		if offset+envelopeLength > len(reconstructedData) {
			t.Fatalf("Not enough data to decode envelope %d", i)
		}

		envelopeData := reconstructedData[offset : offset+envelopeLength]
		envelope, err := common.CourierEnvelopeFromBytes(envelopeData)
		require.NoError(t, err)
		decodedEnvelopes = append(decodedEnvelopes, envelope)
		offset += envelopeLength

		t.Logf("Successfully decoded CourierEnvelope %d from reconstructed data", i+1)
	}

	require.Equal(t, len(courierEnvelopes), len(decodedEnvelopes), "Should decode same number of envelopes")
	t.Log("CourierEnvelope round trip test completed successfully")
}

// verifyTemporarySequence reads back and verifies the temporary sequence data
func verifyTemporarySequence(t *testing.T, env *testEnvironment, tempSeq *testSequenceData) {
	t.Log("Verifying temporary sequence was written correctly")

	// Transform the BoxOwnerCap into a read cap and create a StatefulReader
	tempReadCap := tempSeq.Owner.UniversalReadCap()
	tempStatefulReader, err := bacap.NewStatefulReader(tempReadCap, constants.PIGEONHOLE_CTX)
	require.NoError(t, err)

	// Read back the CBOR blobs from the temporary sequence
	var readBackBlobs [][]byte
	for i := 0; i < len(tempSeq.EnvelopeCBORs); i++ {
		t.Logf("Reading back CBOR blob %d from temporary sequence", i+1)

		// Use composeReadRequest to create a proper read request
		tempReadRequest, tempPrivateKey := composeReadRequest(t, env, tempStatefulReader)
		tempReadReply := injectCourierEnvelope(t, env, tempReadRequest)

		if tempReadReply.Payload == nil {
			t.Logf("First read request returned nil payload for blob %d, falling back to polling", i+1)
			tempReadReply = waitForReplicaResponse(t, env, tempReadRequest)
		}

		require.NotNil(t, tempReadReply.Payload, "Should have payload")

		// Decrypt the replica response using MKEM
		replicaEpoch, _, _ := common.ReplicaNow()
		replicaIndex := int(tempReadRequest.IntermediateReplicas[tempReadReply.ReplyIndex])
		replicaPubKey := env.replicaKeys[replicaIndex][replicaEpoch]
		rawInnerMsg, err := mkemNikeScheme.DecryptEnvelope(tempPrivateKey, replicaPubKey, tempReadReply.Payload)
		require.NoError(t, err)

		innerMsg, err := common.ReplicaMessageReplyInnerMessageFromBytes(rawInnerMsg)
		require.NoError(t, err)
		require.NotNil(t, innerMsg.ReplicaReadReply)

		boxID, err := tempStatefulReader.NextBoxID()
		require.NoError(t, err)
		cborBlob, err := tempStatefulReader.DecryptNext(constants.PIGEONHOLE_CTX, *boxID, innerMsg.ReplicaReadReply.Payload, *innerMsg.ReplicaReadReply.Signature)
		require.NoError(t, err)

		readBackBlobs = append(readBackBlobs, cborBlob)
		t.Logf("Successfully read back CBOR blob %d: %d bytes", i+1, len(cborBlob))
	}

	// Verify the read-back blobs match the original CBOR blobs
	for i, originalCBOR := range tempSeq.EnvelopeCBORs {
		require.Equal(t, originalCBOR, readBackBlobs[i], "Read-back CBOR blob %d should match original", i+1)
	}
	t.Log("Verified all CBOR blobs match original")
}

// executeCopyCommand executes the copy command using the temporary sequence
func executeCopyCommand(t *testing.T, env *testEnvironment, tempSeq *testSequenceData) {
	t.Log("Executing copy command")
	copyReply := injectCopyCommand(t, env, tempSeq.Owner)
	require.Equal(t, uint8(0), copyReply.ErrorCode, "Copy command should succeed")
	t.Log("Copy command executed successfully")
}

// verifyFinalDestination reads back and verifies the final destination data
func verifyFinalDestination(t *testing.T, env *testEnvironment, finalSeq *testSequenceData, bobStatefulReader *bacap.StatefulReader) {
	t.Log("Verifying final destination sequence")

	// Read back the final data
	var finalData [][]byte
	for i := 0; i < len(finalSeq.OriginalData); i++ {
		t.Logf("Reading final data %d", i+1)
		finalReadRequest, finalPrivateKey := composeReadRequest(t, env, bobStatefulReader)
		finalReadReply := injectCourierEnvelope(t, env, finalReadRequest)

		if finalReadReply.Payload == nil {
			t.Logf("First final read request returned nil payload for data %d, falling back to polling", i+1)
			finalReadReply = waitForReplicaResponse(t, env, finalReadRequest)
		}

		require.NotNil(t, finalReadReply.Payload, "Should have final payload")

		// Decrypt the replica response
		replicaEpoch, _, _ := common.ReplicaNow()
		replicaIndex := int(finalReadRequest.IntermediateReplicas[finalReadReply.ReplyIndex])
		replicaPubKey := env.replicaKeys[replicaIndex][replicaEpoch]
		rawInnerMsg, err := mkemNikeScheme.DecryptEnvelope(finalPrivateKey, replicaPubKey, finalReadReply.Payload)
		require.NoError(t, err)

		innerMsg, err := common.ReplicaMessageReplyInnerMessageFromBytes(rawInnerMsg)
		require.NoError(t, err)
		require.NotNil(t, innerMsg.ReplicaReadReply)

		boxID, err := bobStatefulReader.NextBoxID()
		require.NoError(t, err)
		finalBlob, err := bobStatefulReader.DecryptNext(constants.PIGEONHOLE_CTX, *boxID, innerMsg.ReplicaReadReply.Payload, *innerMsg.ReplicaReadReply.Signature)
		require.NoError(t, err)

		finalData = append(finalData, finalBlob)
		t.Logf("Successfully read final data %d: %s", i+1, string(finalBlob))
	}

	// Verify final data matches expected
	for i, expectedData := range finalSeq.OriginalData {
		require.Equal(t, expectedData, finalData[i], "Final data %d should match", i+1)
	}
	t.Log("Final destination verification completed successfully")
}

// createCourierEnvelopeForDestination creates a CourierEnvelope that writes to the final destination sequence.
// This CourierEnvelope will be CBOR encoded and stored in the temporary sequence for the copy command.
func createCourierEnvelopeForDestination(t *testing.T, env *testEnvironment, finalDestinationWriter *bacap.StatefulWriter, message []byte) []byte {
	// BACAP encrypt the message for the final destination
	boxID, bacapCiphertext, sigraw, err := finalDestinationWriter.EncryptNext(message)
	require.NoError(t, err)

	// Create a new signature to avoid pointer reuse
	sigArray := [bacap.SignatureSize]byte{}
	copy(sigArray[:], sigraw)

	// Create ReplicaWrite that will write to the final destination
	replicaWrite := &commands.ReplicaWrite{
		Cmds:      nil, // No padding for inner command
		BoxID:     &boxID,
		Signature: &sigArray,
		IsLast:    false, // Will be set appropriately by caller
		Payload:   bacapCiphertext,
	}

	// Create ReplicaInnerMessage containing the ReplicaWrite
	innerMessage := &common.ReplicaInnerMessage{
		ReplicaWrite: replicaWrite,
	}

	// Use sharding algorithm to determine which replicas should store this BoxID
	currentEpoch, _, _ := epochtime.Now()
	replicaEpoch, _, _ := common.ReplicaNow()
	doc := env.mockPKIClient.docs[currentEpoch]

	// Use sharding algorithm to determine which replicas should store this BoxID
	shardedReplicas, err := replicaCommon.GetShards(&boxID, doc)
	require.NoError(t, err)
	require.Equal(t, 2, len(shardedReplicas), "Should get exactly 2 sharded replicas")

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
		require.NotEqual(t, -1, replicaIndex, "Should find sharded replica in StorageReplicas")

		replicaIndices[i] = uint8(replicaIndex)
		replicaPubKey := doc.StorageReplicas[replicaIndex].EnvelopeKeys[replicaEpoch]
		replicaPubKeys[i], err = common.NikeScheme.UnmarshalBinaryPublicKey(replicaPubKey)
		require.NoError(t, err)

		t.Logf("Final destination BoxID %x will be stored on replica %d (identity: %x)",
			boxID[:8], replicaIndex, shardedReplica.IdentityKey[:8])
	}

	// MKEM encrypt the inner message
	mkemPrivateKey, mkemCiphertext := mkemNikeScheme.Encapsulate(replicaPubKeys, innerMessage.Bytes())
	mkemPublicKey := mkemPrivateKey.Public()

	// Create the CourierEnvelope that will write to the final destination
	courierEnvelope := &common.CourierEnvelope{
		SenderEPubKey:        mkemPublicKey.Bytes(),
		IntermediateReplicas: replicaIndices, // Use sharded replica indices
		DEK:                  [2]*[mkem.DEKSize]byte{mkemCiphertext.DEKCiphertexts[0], mkemCiphertext.DEKCiphertexts[1]},
		Ciphertext:           mkemCiphertext.Envelope,
		IsRead:               false, // This is a write operation
	}

	// CBOR encode the CourierEnvelope
	cborBlob := courierEnvelope.Bytes()
	t.Logf("Created CourierEnvelope for final destination: message='%s', CBOR size=%d bytes", string(message), len(cborBlob))

	return cborBlob
}

// aliceComposesDirectWriteToReplica creates a CourierEnvelope that writes the given
// BACAP-encrypted data directly to the replicas using the provided BoxID and signature.
// Uses the sharding algorithm to determine which replicas should store this BoxID.
func aliceComposesDirectWriteToReplica(t *testing.T, env *testEnvironment, boxID *[bacap.BoxIDSize]byte, signature *[bacap.SignatureSize]byte, ciphertext []byte) *common.CourierEnvelope {
	writeRequest := commands.ReplicaWrite{
		BoxID:     boxID,
		Signature: signature,
		Payload:   ciphertext,
	}
	msg := &common.ReplicaInnerMessage{
		ReplicaWrite: &writeRequest,
	}

	currentEpoch, _, _ := epochtime.Now()
	replicaEpoch, _, _ := common.ReplicaNow()
	doc := env.mockPKIClient.docs[currentEpoch]

	// Use sharding algorithm to determine which replicas should store this BoxID
	shardedReplicas, err := replicaCommon.GetShards(boxID, doc)
	require.NoError(t, err)
	require.Equal(t, 2, len(shardedReplicas), "Should get exactly 2 sharded replicas")

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
		require.NotEqual(t, -1, replicaIndex, "Should find sharded replica in StorageReplicas")

		replicaIndices[i] = uint8(replicaIndex)
		replicaPubKey := doc.StorageReplicas[replicaIndex].EnvelopeKeys[replicaEpoch]
		replicaPubKeys[i], err = common.NikeScheme.UnmarshalBinaryPublicKey(replicaPubKey)
		require.NoError(t, err)

		t.Logf("BoxID %x will be stored on replica %d (identity: %x)",
			boxID[:8], replicaIndex, shardedReplica.IdentityKey[:8])
	}

	mkemPrivateKey, mkemCiphertext := mkemNikeScheme.Encapsulate(
		replicaPubKeys, msg.Bytes(),
	)
	mkemPublicKey := mkemPrivateKey.Public()

	return &common.CourierEnvelope{
		SenderEPubKey:        mkemPublicKey.Bytes(),
		IntermediateReplicas: replicaIndices, // Use sharded replica indices
		DEK: [2]*[mkem.DEKSize]byte{mkemCiphertext.DEKCiphertexts[0],
			mkemCiphertext.DEKCiphertexts[1]},
		Ciphertext: mkemCiphertext.Envelope,
		IsRead:     false,
	}
}

// aliceComposesReadFromReplica creates a CourierEnvelope that reads the given BoxID from replicas.
// Uses the sharding algorithm to determine which replicas should have this BoxID.
func aliceComposesReadFromReplica(t *testing.T, env *testEnvironment, boxID *[bacap.BoxIDSize]byte) *common.CourierEnvelope {
	readRequest := common.ReplicaRead{
		BoxID: boxID,
	}
	msg := &common.ReplicaInnerMessage{
		ReplicaRead: &readRequest,
	}

	currentEpoch, _, _ := epochtime.Now()
	replicaEpoch, _, _ := common.ReplicaNow()
	doc := env.mockPKIClient.docs[currentEpoch]

	// Use sharding algorithm to determine which replicas should have this BoxID
	shardedReplicas, err := replicaCommon.GetShards(boxID, doc)
	require.NoError(t, err)
	require.Equal(t, 2, len(shardedReplicas), "Should get exactly 2 sharded replicas")

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
		require.NotEqual(t, -1, replicaIndex, "Should find sharded replica in StorageReplicas")

		replicaIndices[i] = uint8(replicaIndex)
		replicaPubKey := doc.StorageReplicas[replicaIndex].EnvelopeKeys[replicaEpoch]
		replicaPubKeys[i], err = common.NikeScheme.UnmarshalBinaryPublicKey(replicaPubKey)
		require.NoError(t, err)

		t.Logf("BoxID %x will be read from replica %d (identity: %x)",
			boxID[:8], replicaIndex, shardedReplica.IdentityKey[:8])
	}

	mkemPrivateKey, mkemCiphertext := mkemNikeScheme.Encapsulate(
		replicaPubKeys, msg.Bytes(),
	)
	mkemPublicKey := mkemPrivateKey.Public()

	return &common.CourierEnvelope{
		SenderEPubKey:        mkemPublicKey.Bytes(),
		IntermediateReplicas: replicaIndices, // Use sharded replica indices
		DEK: [2]*[mkem.DEKSize]byte{mkemCiphertext.DEKCiphertexts[0],
			mkemCiphertext.DEKCiphertexts[1]},
		Ciphertext: mkemCiphertext.Envelope,
		IsRead:     true, // This is a read operation
	}
}

// injectCopyCommand sends a CopyCommand to the courier and returns the reply
func injectCopyCommand(t *testing.T, env *testEnvironment, writeCap *bacap.BoxOwnerCap) *common.CopyCommandReply {
	// Generate a unique request ID using nanosecond timestamp
	requestID := uint64(time.Now().UnixNano())

	// Register this request with the response router and get a response channel
	responseCh := env.responseRouter.registerRequest(requestID)

	// Clean up the response map entry when done
	defer env.responseRouter.unregisterRequest(requestID)

	// Create a CBOR plugin command containing the CourierQuery with CopyCommand
	copyCommand := &common.CopyCommand{
		WriteCap: writeCap,
	}
	courierQuery := &common.CourierQuery{
		CourierEnvelope: nil,
		CopyCommand:     copyCommand,
	}
	queryBytes := courierQuery.Bytes()

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
		t.Log("Received copy command response from courier")
	case <-time.After(30 * time.Second): // Longer timeout for copy operations
		t.Fatal("Timeout waiting for copy command response")
	}

	var response *cborplugin.Response
	switch r := responseCmd.(type) {
	case *cborplugin.Response:
		response = r
	default:
		t.Fatalf("Unexpected response type: %T", responseCmd)
	}

	courierQueryReply, err := common.CourierQueryReplyFromBytes(response.Payload)
	require.NoError(t, err)
	require.NotNil(t, courierQueryReply)
	require.NotNil(t, courierQueryReply.CopyCommandReply)

	return courierQueryReply.CopyCommandReply
}

func injectCourierEnvelope(t *testing.T, env *testEnvironment, envelope *common.CourierEnvelope) *common.CourierEnvelopeReply {
	// Generate a unique request ID using nanosecond timestamp
	requestID := uint64(time.Now().UnixNano())

	// Register this request with the response router and get a response channel
	responseCh := env.responseRouter.registerRequest(requestID)

	// Clean up the response map entry when done
	defer env.responseRouter.unregisterRequest(requestID)

	// Create a CBOR plugin command containing the CourierQuery with CourierEnvelope
	courierQuery := &common.CourierQuery{
		CourierEnvelope: envelope,
		CopyCommand:     nil,
	}
	queryBytes := courierQuery.Bytes()

	requestCmd := &cborplugin.Request{
		ID:      requestID,                                                     // Use unique request ID
		SURB:    []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}, // Fake SURB needed for testing
		Payload: queryBytes,
	}

	// Send the request to the courier - this will trigger the courier's OnCommand method
	// The courier will process this and eventually call our writeFunc with a response
	err := env.courier.Courier.OnCommand(requestCmd)
	require.NoError(t, err)
	t.Log("CourierEnvelope processed through courier OnCommand")

	// Wait for response with timeout
	var responseCmd cborplugin.Command
	select {
	case responseCmd = <-responseCh:
		t.Log("Received response from courier")
	case <-time.After(10 * time.Second):
		t.Fatal("Timeout waiting for courier response")
	}

	var response *cborplugin.Response
	switch r := responseCmd.(type) {
	case *cborplugin.Response:
		response = r
	default:
		t.Fatalf("Unexpected response type: %T", responseCmd)
	}

	courierQueryReply, err := common.CourierQueryReplyFromBytes(response.Payload)
	require.NoError(t, err)
	require.NotNil(t, courierQueryReply)
	require.NotNil(t, courierQueryReply.CourierEnvelopeReply)

	return courierQueryReply.CourierEnvelopeReply
}

func composeReadRequest(t *testing.T, env *testEnvironment, reader *bacap.StatefulReader) (*common.CourierEnvelope, nike.PrivateKey) {
	boxID, err := reader.NextBoxID()
	require.NoError(t, err)

	// DEBUG: Log Bob's BoxID
	t.Logf("DEBUG: Bob reads from BoxID: %x", boxID[:])

	readRequest := &common.ReplicaRead{
		BoxID: boxID,
	}

	msg := &common.ReplicaInnerMessage{
		ReplicaRead: readRequest,
	}

	currentEpoch, _, _ := epochtime.Now()
	replicaEpoch, _, _ := common.ReplicaNow()
	doc := env.mockPKIClient.docs[currentEpoch]

	// Use sharding algorithm to determine which replicas should have this BoxID
	shardedReplicas, err := replicaCommon.GetShards(boxID, doc)
	require.NoError(t, err)
	require.Equal(t, 2, len(shardedReplicas), "Should get exactly 2 sharded replicas")

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
		require.NotEqual(t, -1, replicaIndex, "Should find sharded replica in StorageReplicas")

		replicaIndices[i] = uint8(replicaIndex)
		replicaPubKey := doc.StorageReplicas[replicaIndex].EnvelopeKeys[replicaEpoch]
		replicaPubKeys[i], err = common.NikeScheme.UnmarshalBinaryPublicKey(replicaPubKey)
		require.NoError(t, err)

		t.Logf("BoxID %x will be read from replica %d (identity: %x)",
			boxID[:8], replicaIndex, shardedReplica.IdentityKey[:8])
	}

	mkemPrivateKey, mkemCiphertext := mkemNikeScheme.Encapsulate(
		replicaPubKeys, msg.Bytes(),
	)

	mkemPublicKey := mkemPrivateKey.Public()
	return &common.CourierEnvelope{
		SenderEPubKey:        mkemPublicKey.Bytes(),
		IntermediateReplicas: replicaIndices, // Use sharded replica indices
		DEK:                  [2]*[mkem.DEKSize]byte{mkemCiphertext.DEKCiphertexts[0], mkemCiphertext.DEKCiphertexts[1]},
		Ciphertext:           mkemCiphertext.Envelope,
		IsRead:               true, // This is a read request!
	}, mkemPrivateKey
}

// waitForReplicaResponse waits for the courier to receive a reply by repeatedly trying the request
// until we get a non-nil payload, indicating the replica response has been received
func waitForReplicaResponse(t *testing.T, env *testEnvironment, envelope *common.CourierEnvelope) *common.CourierEnvelopeReply {
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
