package cryptoworker_test

import (
	kempem "github.com/katzenpost/hpqc/kem/pem"
	"github.com/katzenpost/hpqc/kem/schemes"
	ecdh "github.com/katzenpost/hpqc/nike/x25519"
	"github.com/katzenpost/hpqc/rand"
	signpem "github.com/katzenpost/hpqc/sign/pem"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"
	aconfig "github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/server"
	"github.com/katzenpost/katzenpost/server/config"
	"github.com/katzenpost/katzenpost/server/internal/cryptoworker"
	"github.com/katzenpost/katzenpost/server/internal/packet"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
)

var testingSchemeName = "xwing"
var testingScheme = schemes.ByName(testingSchemeName)
var testSignatureScheme = signSchemes.ByName("Ed25519")

func TestCryptoWorkerUnwrap(t *testing.T) {
	require := require.New(t)

	// Define geometry for packet creation
	g := geo.GeometryFromUserForwardPayloadLength(
		ecdh.Scheme(rand.Reader),
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

	err = kempem.PublicKeyToFile(filepath.Join(datadir, authLinkPubKeyPem), authLinkPubKey)
	require.NoError(err)

	authPubkey, _, err := testSignatureScheme.GenerateKey()
	require.NoError(err)

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
			Addresses:          []string{"127.0.0.1:1234"},
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
						Addresses:          []string{"127.0.0.1:1234"},
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

	// Test the packet processing
	testPktCount := 100
	for i := 0; i < testPktCount; i++ {
		payload := make([]byte, g.PacketLength)
		fakePacket, err := packet.New(payload, g)
		require.NoError(err, "Packet creation should succeed")

		cryptoWorkerIdx := i % len(cryptoWorkers)
		err = cryptoWorkers[cryptoWorkerIdx].DoUnwrap(fakePacket)
		require.NoError(err, "CryptoWorker should unwrap packet without error")
	}
}
