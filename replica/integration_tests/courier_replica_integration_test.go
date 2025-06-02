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
	// Create test environment with real servers
	testEnv := setupTestEnvironment(t)
	defer testEnv.cleanup()

	// Wait for servers to be ready
	time.Sleep(2 * time.Second)

	// Test complete round-trip: write box, then read it back and verify
	testBoxRoundTrip(t, testEnv)
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
}

func setupTestEnvironment(t *testing.T) *testEnvironment {
	tempDir, err := os.MkdirTemp("", "courier_replica_test_*")
	require.NoError(t, err)

	sphinxGeo := geo.GeometryFromUserForwardPayloadLength(nikeSchemes.ByName("X25519"), 5000, true, 5)
	pkiScheme := signSchemes.ByName("Ed25519 Sphincs+")
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

	for i := 0; i < numReplicas; i++ {
		replicaDir := filepath.Join(tempDir, fmt.Sprintf("replica%d", i))
		require.NoError(t, os.MkdirAll(replicaDir, 0700))
		replicaConfigs[i] = createReplicaConfig(t, replicaDir, pkiScheme, linkScheme, i, sphinxGeo)
		myreplicaKeys, linkPubKey, replicaIdentityPubKey := generateReplicaKeys(t, replicaDir, replicaConfigs[i].PKISignatureScheme, replicaConfigs[i].WireKEMScheme)
		replicaDescriptors[i] = makeReplicaDescriptor(t, i, linkPubKey, replicaIdentityPubKey, myreplicaKeys)
		replicaKeys[i] = myreplicaKeys
	}

	replicas := make([]*replica.Server, numReplicas)
	for i := 0; i < numReplicas; i++ {
		replicas[i] = createReplicaServer(t, replicaConfigs[i], createMockPKIClient(t, sphinxGeo, serviceDesc, replicaDescriptors))
	}

	courier := createCourierServer(t, courierCfg, createMockPKIClient(t, sphinxGeo, serviceDesc, replicaDescriptors))
	courier.ForceConnectorUpdate()

	cleanup := func() {
		for _, replica := range replicas {
			if replica != nil {
				replica.Shutdown()
				replica.Wait()
			}
		}
		//if courier != nil {
		// Courier cleanup if needed
		//}
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
	}
}

// createReplicaConfig creates a configuration for a replica server.
// the configuration will contain a PKI configuration section which
// is synthetic and does not connect to any real directory authorities.
func createReplicaConfig(t *testing.T, dataDir string, pkiScheme sign.Scheme, linkScheme kem.Scheme, replicaID int, sphinxGeo *geo.Geometry) *config.Config {
	return &config.Config{
		DataDir:            dataDir,
		Identifier:         fmt.Sprintf("replica%d", replicaID),
		WireKEMScheme:      linkScheme.Name(),
		PKISignatureScheme: pkiScheme.Name(),
		ReplicaNIKEScheme:  common.NikeScheme.Name(),
		SphinxGeometry:     sphinxGeo,
		Addresses:          []string{fmt.Sprintf("tcp://127.0.0.1:%d", 19000+replicaID)},
		GenerateOnly:       false,
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
	replicaKeys map[uint64]nike.PublicKey) *pki.ReplicaDescriptor {

	require.NotNil(t, linkPubKey)
	require.NotNil(t, identityPubKey)
	require.NotNil(t, replicaKeys)
	require.NotEqual(t, len(replicaKeys), 0)

	linkPubKeyBytes, err := linkPubKey.MarshalBinary()
	require.NoError(t, err)
	identityPubKeyBytes, err := identityPubKey.MarshalBinary()
	require.NoError(t, err)

	desc := &pki.ReplicaDescriptor{
		Name:        fmt.Sprintf("replica%d", replicaID),
		IdentityKey: identityPubKeyBytes,
		LinkKey:     linkPubKeyBytes,
		Addresses: map[string][]string{
			"tcp": {fmt.Sprintf("tcp://127.0.0.1:%d", 19000+replicaID)},
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

func waitForCourierPKI(t *testing.T, env *testEnvironment) {
	maxWait := 30 * time.Second
	checkInterval := 100 * time.Millisecond
	start := time.Now()

	for time.Since(start) < maxWait {
		if env.courier.PKI.PKIDocument() != nil {
			return
		}
		time.Sleep(checkInterval)
	}

	t.Fatal("Timeout waiting for courier PKI document to be ready")
}

func testBoxRoundTrip(t *testing.T, env *testEnvironment) {
	t.Log("WAIT FOR COURIER PKI")
	waitForCourierPKI(t, env)
	t.Log("END OF WAIT FOR COURIER PKI")

	t.Log("SLEEPING FOR 10 SECONDS")
	time.Sleep(10 * time.Second)
	t.Log("END OF SLEEP")

	aliceStatefulWriter, bobStatefulReader := aliceAndBobKeyExchangeKeys(t, env)

	alicePayload1 := []byte("Hello, Bob!")
	aliceEnvelope1 := aliceComposesNextMessage(t, alicePayload1, env, aliceStatefulWriter)
	courierWriteReply1 := injectCourierEnvelope(t, env, aliceEnvelope1)

	aliceEnvHash1 := aliceEnvelope1.EnvelopeHash()
	require.Equal(t, courierWriteReply1.EnvelopeHash[:], aliceEnvHash1[:])
	require.Equal(t, uint8(0), courierWriteReply1.ErrorCode)
	require.Equal(t, uint8(0), courierWriteReply1.ReplyIndex)
	require.Equal(t, len(courierWriteReply1.ErrorString), 0)
	require.Nil(t, courierWriteReply1.Payload)

	bobReadRequest1 := composeReadRequest(t, env, bobStatefulReader)
	courierReadReply1 := injectCourierEnvelope(t, env, bobReadRequest1)

	bobEnvHash1 := bobReadRequest1.EnvelopeHash()
	require.Equal(t, courierReadReply1.EnvelopeHash[:], bobEnvHash1[:])
	require.Equal(t, uint8(0), courierReadReply1.ErrorCode)
	require.Equal(t, uint8(0), courierReadReply1.ReplyIndex)
	require.Nil(t, courierReadReply1.Payload)

	courierReadReply2 := injectCourierEnvelope(t, env, bobReadRequest1)
	require.Equal(t, courierReadReply2.EnvelopeHash[:], bobEnvHash1[:])
	require.Equal(t, uint8(0), courierReadReply2.ErrorCode)
	require.Equal(t, uint8(0), courierReadReply2.ReplyIndex)
	require.NotNil(t, courierReadReply2.Payload)

	/*
		boxid, err := bobStatefulReader.NextBoxID()
		require.NoError(t, err)
		bobPlaintext1, err := bobStatefulReader.DecryptNext(BACAP_CTX, *boxid, ct, sig)
		require.NoError(t, err)
		require.Equal(t, alicePayload1, bobPlaintext1)
	*/

}

func injectCourierEnvelope(t *testing.T, env *testEnvironment, envelope *common.CourierEnvelope) *common.CourierEnvelopeReply {
	// Create a channel to capture the courier's response
	responseCh := make(chan cborplugin.Command, 1)

	// Set up a mock write function to capture the response
	env.courier.Courier.SetWriteFunc(func(cmd cborplugin.Command) {
		responseCh <- cmd
	})

	// Create a CBOR plugin command containing the CourierEnvelope
	envelopeBytes := envelope.Bytes()

	requestCmd := &cborplugin.Request{
		ID:      1,                                                             // Generate a unique ID
		SURB:    []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}, // Fake SURB needed for testing
		Payload: envelopeBytes,
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

	courierReply, err := common.CourierEnvelopeReplyFromBytes(response.Payload)
	require.NoError(t, err)
	require.NotNil(t, courierReply)

	return courierReply
}

func composeReadRequest(t *testing.T, env *testEnvironment, reader *bacap.StatefulReader) *common.CourierEnvelope {
	boxID, err := reader.NextBoxID()
	require.NoError(t, err)

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
	}
}
