package cryptoworker_test

import (
	ecdh "github.com/katzenpost/hpqc/nike/x25519"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/katzenpost/server"
	"github.com/katzenpost/katzenpost/server/config"
	"github.com/katzenpost/katzenpost/server/internal/cryptoworker"
	"testing"

	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/server/internal/packet"
	"github.com/stretchr/testify/require"
)

func TestCryptoWorkerUnwrap(t *testing.T) {
	require := require.New(t) // Set up require instance

	// Define geometry for packet creation
	g := geo.GeometryFromUserForwardPayloadLength(
		ecdh.Scheme(rand.Reader),
		2000,
		true,
		5,
	)

	// Define server configuration
	cfg := &config.Config{
		SphinxGeometry: g,
		Server: &config.Server{
			IsGatewayNode: false,
			IsServiceNode: false,
			Addresses:     []string{"127.0.0.1:29443"},
			Identifier:    "test_node",
			DataDir:       "/tmp/katzenpost",
		},
		Logging: &config.Logging{
			Disable: false,
			File:    "",
			Level:   "DEBUG",
		},
		Debug: &config.Debug{
			NumSphinxWorkers: 5,
		},
	}

	s, err := server.New(cfg)
	require.NoError(err, "Server should be created without error")
	serverGlue := server.NewServerGlue(s)

	inboundPacketsCh := make(chan interface{}, server.InboundPacketsChannelSize)
	// Initialize the crypto worker with the fake Glue
	cryptoWorkersCount := 5
	cryptoWorkers := make([]*cryptoworker.Worker, cryptoWorkersCount)
	for i := 0; i < cryptoWorkersCount; i++ {
		w := cryptoworker.New(serverGlue, inboundPacketsCh, i)
		cryptoWorkers = append(cryptoWorkers, w)
	}

	testPktCount := 100
	for i := 0; i < testPktCount; i++ {
		payload := make([]byte, g.PacketLength)
		fakePacket, err := packet.New(payload, g)
		require.NoError(err, "Packet creation should succeed")
		cryptoWorkerIdx := i % cryptoWorkersCount
		unWrapErr := cryptoWorkers[cryptoWorkerIdx].DoUnwrap(fakePacket)
		require.NoError(unWrapErr, "CryptoWorker should unwrap packet without error")
	}

}
