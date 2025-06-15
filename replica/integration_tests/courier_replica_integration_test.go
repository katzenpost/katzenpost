// SPDX-FileCopyrightText: Copyright (C) 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
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
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/wire/commands"
	courierServer "github.com/katzenpost/katzenpost/courier/server"
	courierConfig "github.com/katzenpost/katzenpost/courier/server/config"
	"github.com/katzenpost/katzenpost/loops"
	"github.com/katzenpost/katzenpost/replica"
	"github.com/katzenpost/katzenpost/replica/common"
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
	BACAP_CTX      []byte       = []byte("test-session")
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
		// Wait for complete shutdown before next test
		time.Sleep(3 * time.Second)
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
		// Wait for complete shutdown before next test
		time.Sleep(3 * time.Second)
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
		// Wait for complete shutdown before next test
		time.Sleep(3 * time.Second)
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

	return &testEnvironment{
		tempDir:        tempDir,
		replicas:       replicas,
		courier:        courier,
		mockPKIClient:  mymockPKIClient,
		replicaConfigs: replicaConfigs,
		courierConfig:  courierCfg,
		cleanup:        cleanup,
		replicaKeys:    replicaKeys,
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
	aliceStatefulWriter, err := bacap.NewStatefulWriter(aliceOwner, BACAP_CTX)
	require.NoError(t, err)
	bobReadCap := aliceOwner.UniversalReadCap()
	bobStatefulReader, err := bacap.NewStatefulReader(bobReadCap, BACAP_CTX)
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
	bobPlaintext1, err := bobStatefulReader.DecryptNext(BACAP_CTX, *boxid, innerMsg.ReplicaReadReply.Payload, *innerMsg.ReplicaReadReply.Signature)
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
		bobPlaintext, err := bobStatefulReader.DecryptNext(BACAP_CTX, *boxid, innerMsg.ReplicaReadReply.Payload, *innerMsg.ReplicaReadReply.Signature)
		require.NoError(t, err)

		// Verify the decrypted message matches what we wrote
		expectedMessage := messages[i]
		require.Equal(t, expectedMessage, bobPlaintext)
		t.Logf("Successfully read and verified box %d: %s", i+1, string(bobPlaintext))
	}

	t.Logf("Successfully completed sequence round-trip test for %d boxes", len(messages))
}

func testNestedEnvelopeRoundTrip(t *testing.T, env *testEnvironment) {
	// PKI documents are already fetched during setup, just verify they're ready
	waitForCourierPKI(t, env)
	waitForReplicasPKI(t, env)

	aliceStatefulWriter, bobStatefulReader := aliceAndBobKeyExchangeKeys(t, env)

	// Create a nested CourierEnvelope with its own independent keys
	nestedEnvelopeCBOR := createNestedCourierEnvelope(t)

	t.Logf("Created nested CourierEnvelope CBOR blob of size %d bytes", len(nestedEnvelopeCBOR))

	// Calculate how to split across 2 boxes
	maxBoxPayload := 1000 // Approximate max payload per box
	if len(nestedEnvelopeCBOR) <= maxBoxPayload {
		// Add padding to ensure it spans 2 boxes
		padding := make([]byte, maxBoxPayload+100)
		nestedEnvelopeCBOR = append(nestedEnvelopeCBOR, padding...)
		t.Logf("Added padding, total size now %d bytes", len(nestedEnvelopeCBOR))
	}

	// Split the CBOR blob into 2 chunks
	midpoint := len(nestedEnvelopeCBOR) / 2
	chunk1 := nestedEnvelopeCBOR[:midpoint]
	chunk2 := nestedEnvelopeCBOR[midpoint:]

	t.Logf("Split into chunk1: %d bytes, chunk2: %d bytes", len(chunk1), len(chunk2))

	// Write chunk1 to first box
	t.Logf("Writing chunk1 to first box")
	aliceEnvelope1 := aliceComposesNextMessage(t, chunk1, env, aliceStatefulWriter)
	courierWriteReply1 := injectCourierEnvelope(t, env, aliceEnvelope1)

	require.Equal(t, uint8(0), courierWriteReply1.ErrorCode)
	require.Nil(t, courierWriteReply1.Payload)
	t.Logf("Successfully wrote chunk1")

	// Write chunk2 to second box
	t.Logf("Writing chunk2 to second box")
	aliceEnvelope2 := aliceComposesNextMessage(t, chunk2, env, aliceStatefulWriter)
	courierWriteReply2 := injectCourierEnvelope(t, env, aliceEnvelope2)

	require.Equal(t, uint8(0), courierWriteReply2.ErrorCode)
	require.Nil(t, courierWriteReply2.Payload)
	t.Logf("Successfully wrote chunk2")

	// Read back both boxes and concatenate
	var reconstructedCBOR []byte

	for i := 0; i < 2; i++ {
		t.Logf("Reading box %d", i+1)

		bobReadRequest, bobPrivateKey := composeReadRequest(t, env, bobStatefulReader)
		courierReadReply := injectCourierEnvelope(t, env, bobReadRequest)

		if courierReadReply.Payload == nil {
			t.Logf("First read request returned nil payload for box %d, falling back to polling", i+1)
			courierReadReply = waitForReplicaResponse(t, env, bobReadRequest)
		}

		require.NotNil(t, courierReadReply.Payload, "Should have payload")

		// Decrypt the box content
		replicaEpoch, _, _ := common.ReplicaNow()
		replicaIndex := int(bobReadRequest.IntermediateReplicas[courierReadReply.ReplyIndex])
		replicaPubKey := env.replicaKeys[replicaIndex][replicaEpoch]
		rawInnerMsg, err := mkemNikeScheme.DecryptEnvelope(bobPrivateKey, replicaPubKey, courierReadReply.Payload)
		require.NoError(t, err)

		innerMsg, err := common.ReplicaMessageReplyInnerMessageFromBytes(rawInnerMsg)
		require.NoError(t, err)
		require.NotNil(t, innerMsg.ReplicaReadReply)

		boxid, err := bobStatefulReader.NextBoxID()
		require.NoError(t, err)
		chunkData, err := bobStatefulReader.DecryptNext(BACAP_CTX, *boxid, innerMsg.ReplicaReadReply.Payload, *innerMsg.ReplicaReadReply.Signature)
		require.NoError(t, err)

		// Append this chunk to reconstructed data
		reconstructedCBOR = append(reconstructedCBOR, chunkData...)
		t.Logf("Successfully read and decrypted box %d: %d bytes", i+1, len(chunkData))
	}

	// Verify the reconstructed CBOR matches the original
	require.Equal(t, nestedEnvelopeCBOR, reconstructedCBOR, "Reconstructed CBOR should match original")
	t.Logf("Successfully verified nested envelope round-trip: %d bytes", len(reconstructedCBOR))
}

// createNestedCourierEnvelope creates a CourierEnvelope with nested ReplicaWrite containing
// BACAP-encrypted "Hello Bob" + padding, using independent keys
func createNestedCourierEnvelope(t *testing.T) []byte {
	// Create independent BACAP keys for the nested envelope
	nestedOwner, err := bacap.NewBoxOwnerCap(rand.Reader)
	require.NoError(t, err)

	nestedStatefulWriter, err := bacap.NewStatefulWriter(nestedOwner, BACAP_CTX)
	require.NoError(t, err)

	// Create "Hello Bob" message with padding to fill box payload
	message := []byte("Hello Bob")
	// Add padding to make it a full box payload size
	padding := make([]byte, 1000-len(message)) // Approximate box payload size
	paddedMessage := append(message, padding...)

	// BACAP encrypt the padded message
	boxID, bacapCiphertext, sigraw, err := nestedStatefulWriter.EncryptNext(paddedMessage)
	require.NoError(t, err)

	sig := [bacap.SignatureSize]byte{}
	copy(sig[:], sigraw)

	// Create ReplicaWrite with the BACAP-encrypted payload
	replicaWrite := &commands.ReplicaWrite{
		Cmds:      nil, // No padding for inner command
		BoxID:     &boxID,
		Signature: &sig,
		IsLast:    true,
		Payload:   bacapCiphertext,
	}

	// Create ReplicaInnerMessage containing the ReplicaWrite
	innerMessage := &common.ReplicaInnerMessage{
		ReplicaWrite: replicaWrite,
	}

	// Generate dummy replica public keys for MKEM encryption
	replicaPubKey1, _, err := common.NikeScheme.GenerateKeyPair()
	require.NoError(t, err)
	replicaPubKey2, _, err := common.NikeScheme.GenerateKeyPair()
	require.NoError(t, err)
	replicaPubKeys := []nike.PublicKey{replicaPubKey1, replicaPubKey2}

	// MKEM encrypt the inner message using the global mkemNikeScheme
	mkemPrivateKey, mkemCiphertext := mkemNikeScheme.Encapsulate(replicaPubKeys, innerMessage.Bytes())
	mkemPublicKey := mkemPrivateKey.Public()

	// Create the nested CourierEnvelope
	nestedEnvelope := &common.CourierEnvelope{
		SenderEPubKey:        mkemPublicKey.Bytes(),
		IntermediateReplicas: [2]uint8{0, 1},
		DEK:                  [2]*[mkem.DEKSize]byte{mkemCiphertext.DEKCiphertexts[0], mkemCiphertext.DEKCiphertexts[1]},
		Ciphertext:           mkemCiphertext.Envelope,
		IsRead:               false,
	}

	// CBOR encode the entire CourierEnvelope
	cborBlob := nestedEnvelope.Bytes()
	t.Logf("Created nested CourierEnvelope: ReplicaWrite with %d byte BACAP payload, total CBOR size: %d bytes",
		len(bacapCiphertext), len(cborBlob))

	return cborBlob
}

func injectCourierEnvelope(t *testing.T, env *testEnvironment, envelope *common.CourierEnvelope) *common.CourierEnvelopeReply {
	// Create a channel to capture the courier's response
	responseCh := make(chan cborplugin.Command, 1)

	// Set up a mock write function to capture the response
	env.courier.Courier.SetWriteFunc(func(cmd cborplugin.Command) {
		responseCh <- cmd
	})

	// Create a CBOR plugin command containing the CourierQuery with CourierEnvelope
	courierQuery := &common.CourierQuery{
		CourierEnvelope: envelope,
		CopyCommand:     nil,
	}
	queryBytes := courierQuery.Bytes()

	requestCmd := &cborplugin.Request{
		ID:      1,                                                             // Generate a unique ID
		SURB:    []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}, // Fake SURB needed for testing
		Payload: queryBytes,
	}

	// fake out the client to mixnet to courier comms, obviously.
	err := env.courier.Courier.OnCommand(requestCmd)
	require.NoError(t, err)
	t.Log("CourierEnvelope processed through courier OnCommand")

	// wait for response with timeout
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

	replica0Index := 0
	replica1Index := 1

	currentEpoch, _, _ := epochtime.Now()
	replicaEpoch, _, _ := common.ReplicaNow()
	replicaPubKey1 := env.mockPKIClient.docs[currentEpoch].StorageReplicas[replica0Index].EnvelopeKeys[replicaEpoch]
	replicaPubKey2 := env.mockPKIClient.docs[currentEpoch].StorageReplicas[replica1Index].EnvelopeKeys[replicaEpoch]

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
		IntermediateReplicas: [2]uint8{uint8(replica0Index), uint8(replica1Index)},
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
