package cryptoworker_test

import (
	gorand "crypto/rand"
	"fmt"
	"github.com/katzenpost/hpqc/nike"
	"github.com/stretchr/testify/assert"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	kempem "github.com/katzenpost/hpqc/kem/pem"
	"github.com/katzenpost/hpqc/kem/schemes"
	ecdh "github.com/katzenpost/hpqc/nike/x25519"
	"github.com/katzenpost/hpqc/rand"
	signpem "github.com/katzenpost/hpqc/sign/pem"

	signSchemes "github.com/katzenpost/hpqc/sign/schemes"
	aconfig "github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/sphinx"
	"github.com/katzenpost/katzenpost/core/sphinx/commands"
	"github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/server"
	"github.com/katzenpost/katzenpost/server/config"
	"github.com/katzenpost/katzenpost/server/internal/cryptoworker"
	"github.com/katzenpost/katzenpost/server/internal/packet"
)

var testingSchemeName = "xwing"
var testingScheme = schemes.ByName(testingSchemeName)
var testSignatureScheme = signSchemes.ByName("Ed25519")

func TestCryptoWorkerUnwrap(t *testing.T) {
	require := require.New(t)

	mynike := ecdh.Scheme(rand.Reader)

	// Define geometry for packet creation
	g := geo.GeometryFromUserForwardPayloadLength(
		mynike,
		2000,
		true,
		5,
	)

	datadir, err := os.MkdirTemp("", "server_data_dir")
	require.NoError(err)

	authLinkPubKeyPem := "auth_link_pub_key.pem"

	scheme := testingScheme
	authLinkPubKey, _, err := scheme.GenerateKeyPair()
	require.NoError(err)
	require.NotNil(authLinkPubKeyPem)

	err = kempem.PublicKeyToFile(filepath.Join(datadir, authLinkPubKeyPem), authLinkPubKey)
	require.NoError(err)

	authPubkey, _, err := testSignatureScheme.GenerateKey()
	require.NoError(err)
	require.NotNil(authPubkey)

	authIDPubKeyPem := "auth_id_pub_key.pem"
	authkeyPath := filepath.Join(datadir, authIDPubKeyPem)

	err = signpem.PublicKeyToFile(authkeyPath, authPubkey)
	require.NoError(err)

	mixIdPublicKey, mixIdPrivateKey, err := testSignatureScheme.GenerateKey()
	require.NoError(err)
	err = signpem.PrivateKeyToFile(filepath.Join(datadir, "identity.private.pem"), mixIdPrivateKey)
	require.NoError(err)
	err = signpem.PublicKeyToFile(filepath.Join(datadir, "identity.public.pem"), mixIdPublicKey)
	require.NoError(err)

	// Define server configuration
	cfg := &config.Config{
		Management: &config.Management{
			Enable: false,
		},
		SphinxGeometry: g,
		Server: &config.Server{
			WireKEM:            testingSchemeName,
			PKISignatureScheme: testSignatureScheme.Name(),
			Identifier:         "testserver",
			Addresses:          []string{"127.0.0.1:2955"},
			DataDir:            datadir,
			IsGatewayNode:      false,
		},
		Logging: &config.Logging{
			Disable: false,
			File:    "",
			Level:   "DEBUG",
		},
		Gateway: nil,
		PKI: &config.PKI{
			Voting: &config.Voting{
				Authorities: []*aconfig.Authority{
					&aconfig.Authority{
						WireKEMScheme:      testingSchemeName,
						PKISignatureScheme: testSignatureScheme.Name(),
						Identifier:         "auth1",
						IdentityPublicKey:  authPubkey,
						LinkPublicKey:      authLinkPubKey,
						Addresses:          []string{"127.0.0.1:2955"},
					},
				},
			},
		},
		Debug: &config.Debug{
			NumSphinxWorkers:             1,
			NumGatewayWorkers:            0,
			NumServiceWorkers:            0,
			NumKaetzchenWorkers:          1,
			SchedulerExternalMemoryQueue: false,
			SchedulerQueueSize:           0,
			SchedulerMaxBurst:            16,
			UnwrapDelay:                  10,
			GatewayDelay:                 0,
			ServiceDelay:                 0,
			KaetzchenDelay:               750,
			SchedulerSlack:               10,
			SendSlack:                    50,
			DecoySlack:                   15 * 1000,
			ConnectTimeout:               60 * 1000,
			HandshakeTimeout:             30 * 1000,
			ReauthInterval:               30 * 1000,
			SendDecoyTraffic:             false,
			DisableRateLimit:             true,
			GenerateOnly:                 false,
		},
	}

	err = cfg.FixupAndValidate()
	require.NoError(err)

	s, err := server.New(cfg)
	require.NoError(err, "Server should be created without error")
	serverGlue := server.NewServerGlue(s)

	inboundPacketsCh := make(chan interface{}, cfg.Debug.NumSphinxWorkers)
	cryptoWorkers := make([]*cryptoworker.Worker, cfg.Debug.NumSphinxWorkers)

	// Initialize the crypto workers
	for i := range cryptoWorkers {
		cryptoWorkers[i] = cryptoworker.New(serverGlue, inboundPacketsCh, i)
	}

	sphinxInstance := sphinx.NewSphinx(g)

	// Generate a path with random public keys for each node
	nrHops := 5
	path := newNikePathVector(require, mynike, nrHops, false)

	// Create a valid Sphinx packet
	payload := make([]byte, g.ForwardPayloadLength)
	_, err = gorand.Read(payload) // Simulate a random payload
	require.NoError(err)

	// Simulate multiple packets
	numPackets := 10
	errCh := make(chan error, numPackets) // Channel to collect errors
	for i := 0; i < numPackets; i++ {
		go func(cryptoWorkerIdx int) {
			packetBytes, err := sphinxInstance.NewPacket(rand.Reader, path, payload)
			if err != nil {
				errCh <- fmt.Errorf("failed to create packet: %w", err)
				return
			}

			testPacket, err := packet.New(packetBytes, g)
			if err != nil {
				errCh <- fmt.Errorf("failed to create packet structure: %w", err)
				return
			}

			err = cryptoWorkers[cryptoWorkerIdx].DoUnwrap(testPacket)
			if err != nil {
				errCh <- fmt.Errorf("cryptoWorker should unwrap packet without error: %w", err)
				return
			}

			errCh <- nil

		}(i % len(cryptoWorkers))
	}

	// Check all errors
	for i := 0; i < numPackets; i++ {
		err := <-errCh
		assert.NoError(t, err, "CryptoWorker should unwrap packet without error")
	}
}

func newNikePathVector(require *require.Assertions, mynike nike.Scheme, nrHops int, isSURB bool) []*sphinx.PathHop {
	const delayBase = 0xdeadbabe

	// Generate the keypairs and node identifiers for the "nodes".
	nodes := make([]*nodeParams, nrHops)
	for i := range nodes {
		nodes[i] = newNikeNode(require, mynike)
	}

	// Assemble the path vector.
	path := make([]*sphinx.PathHop, nrHops)
	for i := range path {
		path[i] = new(sphinx.PathHop)
		copy(path[i].ID[:], nodes[i].id[:])
		path[i].NIKEPublicKey = nodes[i].publicKey
		if i < nrHops-1 {
			// Non-terminal hop, add the delay.
			delay := new(commands.NodeDelay)
			delay.Delay = delayBase * uint32(i+1)
			path[i].Commands = append(path[i].Commands, delay)
		} else {
			// Terminal hop, add the recipient.
			recipient := new(commands.Recipient)
			_, err := gorand.Read(recipient.ID[:])
			require.NoError(err, "failed to generate recipient")
			path[i].Commands = append(path[i].Commands, recipient)

			// This is a SURB, add a surb_reply.
			if isSURB {
				surbReply := new(commands.SURBReply)
				_, err := gorand.Read(surbReply.ID[:])
				require.NoError(err, "failed to generate surb_reply")
				path[i].Commands = append(path[i].Commands, surbReply)
			}
		}
	}

	return path
}

type nodeParams struct {
	id         [constants.NodeIDLength]byte
	privateKey nike.PrivateKey
	publicKey  nike.PublicKey
}

func newNikeNode(require *require.Assertions, mynike nike.Scheme) *nodeParams {
	n := new(nodeParams)

	_, err := gorand.Read(n.id[:])
	require.NoError(err, "newNikeNode(): failed to generate ID")
	n.publicKey, n.privateKey, err = mynike.GenerateKeyPair()
	require.NoError(err, "newNikeNode(): NewKeypair() failed")
	return n
}
