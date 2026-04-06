// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client2

import (
	"context"
	"errors"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/kem"
	kemSchemes "github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/hpqc/sign"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"

	vServerConfig "github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/client2/config"
	"github.com/katzenpost/katzenpost/core/cert"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/log"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/core/wire/commands"
	pigeonholeGeo "github.com/katzenpost/katzenpost/pigeonhole/geo"
)

// document contains fields from Document but not the encoding.BinaryMarshaler methods
type document cpki.Document

func generateDescriptor(t *testing.T, pkiScheme sign.Scheme, linkScheme kem.Scheme, sphinxNikeScheme nike.Scheme, sphinxKemScheme kem.Scheme) *cpki.MixDescriptor {
	idkey := make([]byte, pkiScheme.PublicKeySize())
	_, err := rand.Reader.Read(idkey)
	require.NoError(t, err)

	linkkey := make([]byte, linkScheme.PublicKeySize())
	_, err = rand.Reader.Read(linkkey)
	require.NoError(t, err)

	return &cpki.MixDescriptor{
		Name:        "fake mix node name",
		IdentityKey: idkey,
		LinkKey:     linkkey,
		Addresses:   map[string][]string{"tcp": []string{"tcp://127.0.0.1:12345"}},
	}
}

func generateDocument(t *testing.T, pkiScheme sign.Scheme, linkScheme kem.Scheme, replicaScheme nike.Scheme, sphinxNikeScheme nike.Scheme, sphinxKemScheme kem.Scheme, numDirAuths, numMixNodes, numStorageReplicas int, geo *geo.Geometry, epoch uint64) *cpki.Document {
	mixNodes := make([]*cpki.MixDescriptor, numMixNodes)
	for i := 0; i < numMixNodes; i++ {
		mixNodes[i] = generateDescriptor(t, pkiScheme, linkScheme, sphinxNikeScheme, sphinxKemScheme)
	}
	topology := make([][]*cpki.MixDescriptor, 1)
	topology[0] = mixNodes

	srv := make([]byte, 32)
	_, err := rand.Reader.Read(srv)
	require.NoError(t, err)
	oldhashes := [][]byte{srv, srv}

	return &cpki.Document{
		Epoch:        epoch,
		GenesisEpoch: epoch,

		SendRatePerMinute: 0,
		Mu:                1,
		MuMaxDelay:        1,
		LambdaP:           1,
		LambdaPMaxDelay:   1,
		LambdaL:           1,
		LambdaLMaxDelay:   1,
		LambdaD:           1,
		LambdaDMaxDelay:   1,
		LambdaM:           1,
		LambdaMMaxDelay:   1,
		LambdaG:           1,
		LambdaGMaxDelay:   1,

		Topology:           topology,
		StorageReplicas:    []*cpki.ReplicaDescriptor{},
		SharedRandomValue:  srv,
		PriorSharedRandom:  oldhashes,
		SphinxGeometryHash: geo.Hash(),
		PKISignatureScheme: pkiScheme.Name(),

		Version: cpki.DocumentVersion,
	}
}

type authenticator struct {
	log *logging.Logger

	pubkey  kem.PublicKey
	privkey kem.PrivateKey
}

func (a *authenticator) IsPeerValid(creds *wire.PeerCredentials) bool {
	return true // XXX
}

// setupTestGateway creates a mock gateway server and client config for connection tests.
// The handler func is called for each GetConsensus2 request and must send the response.
func setupTestGateway(t *testing.T, gwAddr string, handler func(t *testing.T, wireConn *wire.Session, cmds *commands.Commands, mycmd *commands.GetConsensus2)) (*config.Config, map[uint64][]byte) {
	docs := make(map[uint64][]byte)

	logbackend, err := log.New("", "DEBUG", false)
	require.NoError(t, err)

	WireKEMSchemeName := "x25519"
	linkScheme := kemSchemes.ByName(WireKEMSchemeName)

	gwlinkPubKey, gwlinkPrivKey, err := linkScheme.GenerateKeyPair()
	require.NoError(t, err)

	authlinkPubKey, _, err := linkScheme.GenerateKeyPair()
	require.NoError(t, err)

	auth := &authenticator{
		log:     logbackend.GetLogger("authenticator"),
		pubkey:  gwlinkPubKey,
		privkey: gwlinkPrivKey,
	}

	pkiSchemeName := "ed25519"
	pkiScheme := signSchemes.ByName(pkiSchemeName)
	idPubKey, _, err := pkiScheme.GenerateKey()
	require.NoError(t, err)

	id := hash.Sum256From(idPubKey)

	auth1IdPubKey, _, err := pkiScheme.GenerateKey()
	require.NoError(t, err)

	auth2IdPubKey, _, err := pkiScheme.GenerateKey()
	require.NoError(t, err)

	auth3IdPubKey, _, err := pkiScheme.GenerateKey()
	require.NoError(t, err)

	nikeScheme := schemes.ByName("x25519")
	g := geo.GeometryFromUserForwardPayloadLength(nikeScheme, 2000, false, 5)

	pigeonholeGeometry, err := pigeonholeGeo.NewGeometryFromSphinx(g, nikeScheme)
	require.NoError(t, err)

	clientCfg := &config.Config{
		ListenNetwork:      "tcp",
		ListenAddress:      "127.0.0.1:0",
		PKISignatureScheme: "ed25519",
		WireKEMScheme:      "x25519",
		SphinxGeometry:     g,
		PigeonholeGeometry: pigeonholeGeometry,
		Logging: &config.Logging{
			Disable: false,
			File:    "",
			Level:   "DEBUG",
		},
		UpstreamProxy: &config.UpstreamProxy{},
		Debug: &config.Debug{
			EnableTimeSync: true,
		},
		CachedDocument: nil,
		PinnedGateways: &config.Gateways{
			Gateways: []*config.Gateway{
				{
					WireKEMScheme:      WireKEMSchemeName,
					Name:               "gateway",
					IdentityKey:        idPubKey,
					LinkKey:            gwlinkPubKey,
					PKISignatureScheme: pkiSchemeName,
					Addresses:          []string{gwAddr},
				},
			},
		},
		VotingAuthority: &config.VotingAuthority{
			Peers: []*vServerConfig.Authority{
				{
					Identifier:         "auth1",
					IdentityPublicKey:  auth1IdPubKey,
					PKISignatureScheme: pkiSchemeName,
					LinkPublicKey:      authlinkPubKey,
					WireKEMScheme:      WireKEMSchemeName,
					Addresses:          []string{"tcp://127.0.0.1:1301"},
				},
				{
					Identifier:         "auth2",
					IdentityPublicKey:  auth2IdPubKey,
					PKISignatureScheme: pkiSchemeName,
					LinkPublicKey:      authlinkPubKey,
					WireKEMScheme:      WireKEMSchemeName,
					Addresses:          []string{"tcp://127.0.0.1:1302"},
				},
				{
					Identifier:         "auth3",
					IdentityPublicKey:  auth3IdPubKey,
					PKISignatureScheme: pkiSchemeName,
					LinkPublicKey:      authlinkPubKey,
					WireKEMScheme:      WireKEMSchemeName,
					Addresses:          []string{"tcp://127.0.0.1:1303"},
				},
			},
		},
		Callbacks:          nil,
		PreferedTransports: nil,
	}

	go func() {
		u, err := url.Parse(gwAddr)
		require.NoError(t, err)

		l, err := net.Listen("tcp", u.Host)
		require.NoError(t, err)
		defer l.Close()

		conn, err := l.Accept()
		require.NoError(t, err)

		cfg := &wire.SessionConfig{
			KEMScheme:          linkScheme,
			PKISignatureScheme: pkiScheme,
			Geometry:           g,
			Authenticator:      auth,
			AdditionalData:     id[:],
			AuthenticationKey:  gwlinkPrivKey,
			RandomReader:       rand.Reader,
		}
		wireConn, err := wire.NewSession(cfg, false)
		require.NoError(t, err)

		err = wireConn.Initialize(conn)
		require.NoError(t, err)

		cmds := commands.NewMixnetCommands(g)

		for {
			cmd, err := wireConn.RecvCommand()
			if err != nil {
				return
			}
			if cmd == nil {
				return
			}

			switch mycmd := cmd.(type) {
			case *commands.NoOp:
				continue
			case *commands.Disconnect:
				return
			case *commands.RetrieveMessage:
				resp := &commands.MessageEmpty{
					Cmds:     cmds,
					Sequence: mycmd.Sequence,
				}
				if err = wireConn.SendCommand(resp); err != nil {
					return
				}
			case *commands.GetConsensus2:
				handler(t, wireConn, cmds, mycmd)
			default:
				return
			}
		}
	}()

	return clientCfg, docs
}

func setupClientCallbacks(cfg *config.Config) {
	cfg.Callbacks = &config.Callbacks{}
	cfg.Callbacks.OnConnFn = func(err error) {}
	cfg.Callbacks.OnDocumentFn = func(*cpki.Document) {}
	cfg.Callbacks.OnEmptyFn = func() error { return nil }
	cfg.Callbacks.OnMessageFn = func([]byte) error { return nil }
	cfg.Callbacks.OnACKFn = func(*[constants.SURBIDLength]byte, []byte) error { return nil }
}

func TestConnectionConsensusGoneSurvives(t *testing.T) {
	gwAddr := "tcp://127.0.0.1:12346"
	requestCount := 0

	pkiSchemeName := "ed25519"
	pkiScheme := signSchemes.ByName(pkiSchemeName)

	auth1IdPubKey, auth1IdPrivKey, err := pkiScheme.GenerateKey()
	require.NoError(t, err)
	auth2IdPubKey, auth2IdPrivKey, err := pkiScheme.GenerateKey()
	require.NoError(t, err)
	auth3IdPubKey, auth3IdPrivKey, err := pkiScheme.GenerateKey()
	require.NoError(t, err)

	nikeScheme := schemes.ByName("x25519")
	linkScheme := kemSchemes.ByName("x25519")
	g := geo.GeometryFromUserForwardPayloadLength(nikeScheme, 2000, false, 5)

	clientCfg, _ := setupTestGateway(t, gwAddr, func(t *testing.T, wireConn *wire.Session, cmds *commands.Commands, mycmd *commands.GetConsensus2) {
		requestCount++
		if requestCount == 1 {
			// First request: return ConsensusGone.
			resp := &commands.Consensus2{
				Cmds:       cmds,
				ErrorCode:  commands.ConsensusGone,
				ChunkNum:   0,
				ChunkTotal: 1,
				Payload:    []byte{},
			}
			err := wireConn.SendCommand(resp)
			require.NoError(t, err)
			return
		}

		// Subsequent requests: return a valid document.
		replicaScheme := schemes.ByName("x25519")
		doc := generateDocument(t, pkiScheme, linkScheme, replicaScheme, nikeScheme, nil, 3, 3, 0, g, mycmd.Epoch)

		docBytes, err := ccbor.Marshal((*document)(doc))
		require.NoError(t, err)

		rawcert, err := cert.Sign(auth1IdPrivKey, auth1IdPubKey, docBytes, mycmd.Epoch+5)
		require.NoError(t, err)
		rawcert, err = cert.SignMulti(auth2IdPrivKey, auth2IdPubKey, rawcert)
		require.NoError(t, err)
		rawcert, err = cert.SignMulti(auth3IdPrivKey, auth3IdPubKey, rawcert)
		require.NoError(t, err)

		chunkSize := cmds.MaxMessageLenServerToClient
		chunks, err := cpki.Chunk(rawcert, chunkSize)
		require.NoError(t, err)

		for i, chunk := range chunks {
			resp := &commands.Consensus2{
				Cmds:       cmds,
				ErrorCode:  commands.ConsensusOk,
				ChunkNum:   uint32(i),
				ChunkTotal: uint32(len(chunks)),
				Payload:    chunk,
			}
			err = wireConn.SendCommand(resp)
			require.NoError(t, err)
		}
	})

	// Override the auth keys in the config to match our signing keys.
	clientCfg.VotingAuthority.Peers[0].IdentityPublicKey = auth1IdPubKey
	clientCfg.VotingAuthority.Peers[1].IdentityPublicKey = auth2IdPubKey
	clientCfg.VotingAuthority.Peers[2].IdentityPublicKey = auth3IdPubKey

	setupClientCallbacks(clientCfg)

	logbackend, err := log.New("", "DEBUG", false)
	require.NoError(t, err)

	c, err := New(clientCfg, logbackend)
	require.NoError(t, err)

	time.Sleep(time.Second)

	err = c.Start()
	require.NoError(t, err)

	// Wait for the client to recover from ConsensusGone and fetch a valid doc.
	time.Sleep(time.Second * 5)

	_, doc := c.CurrentDocument()
	require.NotNil(t, doc, "client should have recovered and fetched a document after ConsensusGone")
	require.True(t, requestCount >= 2, "gateway should have received at least 2 GetConsensus2 requests")

	c.Shutdown()
}

func TestConnection(t *testing.T) {
	docs := make(map[uint64][]byte)

	logbackend, err := log.New("", "DEBUG", false)
	require.NoError(t, err)

	WireKEMSchemeName := "x25519"
	linkScheme := kemSchemes.ByName(WireKEMSchemeName)

	gwlinkPubKey, gwlinkPrivKey, err := linkScheme.GenerateKeyPair()
	require.NoError(t, err)

	authlinkPubKey, _, err := linkScheme.GenerateKeyPair()
	require.NoError(t, err)

	auth := &authenticator{
		log:     logbackend.GetLogger("authenticator"),
		pubkey:  gwlinkPubKey,
		privkey: gwlinkPrivKey,
	}

	pkiSchemeName := "ed25519"
	pkiScheme := signSchemes.ByName(pkiSchemeName)
	idPubKey, _, err := pkiScheme.GenerateKey()
	require.NoError(t, err)

	id := hash.Sum256From(idPubKey)

	auth1IdPubKey, auth1IdPrivKey, err := pkiScheme.GenerateKey()
	require.NoError(t, err)

	auth2IdPubKey, auth2IdPrivKey, err := pkiScheme.GenerateKey()
	require.NoError(t, err)

	auth3IdPubKey, auth3IdPrivKey, err := pkiScheme.GenerateKey()
	require.NoError(t, err)

	nikeScheme := schemes.ByName("x25519")
	g := geo.GeometryFromUserForwardPayloadLength(nikeScheme, 2000, false, 5)

	gwAddr := "tcp://127.0.0.1:1234"

	replicaScheme := schemes.ByName("x25519")
	sphinxNikeScheme := schemes.ByName("x25519")
	numDirAuths := 3
	numMixNodes := 3
	numStorageReplicas := 0

	// Compute pigeonhole geometry from sphinx geometry for test
	pigeonholeGeometry, err := pigeonholeGeo.NewGeometryFromSphinx(g, sphinxNikeScheme)
	require.NoError(t, err)

	clientCfg := &config.Config{
		ListenNetwork:      "tcp",
		ListenAddress:      "127.0.0.1:63445",
		PKISignatureScheme: "ed25519",
		WireKEMScheme:      "x25519",
		SphinxGeometry:     g,
		PigeonholeGeometry: pigeonholeGeometry,
		Logging: &config.Logging{
			Disable: false,
			File:    "",
			Level:   "DEBUG",
		},
		UpstreamProxy: &config.UpstreamProxy{},
		Debug: &config.Debug{
			EnableTimeSync: true,
		},
		CachedDocument: nil,
		PinnedGateways: &config.Gateways{
			Gateways: []*config.Gateway{
				&config.Gateway{
					WireKEMScheme:      WireKEMSchemeName,
					Name:               "gateway",
					IdentityKey:        idPubKey,
					LinkKey:            gwlinkPubKey,
					PKISignatureScheme: pkiSchemeName,
					Addresses:          []string{gwAddr},
				},
			},
		},
		VotingAuthority: &config.VotingAuthority{
			Peers: []*vServerConfig.Authority{
				&vServerConfig.Authority{
					Identifier:         "auth1",
					IdentityPublicKey:  auth1IdPubKey,
					PKISignatureScheme: pkiSchemeName,
					LinkPublicKey:      authlinkPubKey,
					WireKEMScheme:      WireKEMSchemeName,
					Addresses:          []string{"tcp://127.0.0.1:1301"},
				},
				&vServerConfig.Authority{
					Identifier:         "auth2",
					IdentityPublicKey:  auth2IdPubKey,
					PKISignatureScheme: pkiSchemeName,
					LinkPublicKey:      authlinkPubKey,
					WireKEMScheme:      WireKEMSchemeName,
					Addresses:          []string{"tcp://127.0.0.1:1302"},
				},
				&vServerConfig.Authority{
					Identifier:         "auth3",
					IdentityPublicKey:  auth3IdPubKey,
					PKISignatureScheme: pkiSchemeName,
					LinkPublicKey:      authlinkPubKey,
					WireKEMScheme:      WireKEMSchemeName,
					Addresses:          []string{"tcp://127.0.0.1:1303"},
				},
			},
		},
		Callbacks:          nil,
		PreferedTransports: nil,
	}

	go func() {
		u, err := url.Parse(gwAddr)
		require.NoError(t, err)

		t.Logf("listening on %s", u.Host)
		l, err := net.Listen("tcp", u.Host)
		require.NoError(t, err)

		conn, err := l.Accept()
		require.NoError(t, err)

		cfg := &wire.SessionConfig{
			KEMScheme:          linkScheme,
			PKISignatureScheme: pkiScheme,
			Geometry:           g,
			Authenticator:      auth,
			AdditionalData:     id[:],
			AuthenticationKey:  gwlinkPrivKey,
			RandomReader:       rand.Reader,
		}
		wireConn, err := wire.NewSession(cfg, false)
		require.NoError(t, err)

		err = wireConn.Initialize(conn)
		require.NoError(t, err)

		cmds := commands.NewMixnetCommands(g)

	loop:
		for {
			cmd, err := wireConn.RecvCommand()
			//require.NoError(t, err)
			if err != nil {
				return
			}

			if cmd == nil {
				return
			}

			switch mycmd := cmd.(type) {
			case *commands.NoOp:
				continue
			case *commands.Disconnect:
				break loop
			case *commands.SendPacket:
				panic("SendPacket wtf")
			case *commands.RetrieveMessage:
				resp := &commands.MessageEmpty{
					Cmds:     cmds,
					Sequence: 0,
				}
				err = wireConn.SendCommand(resp)
				require.NoError(t, err)
			case *commands.SendRetrievePacket:
				panic("SendRetrievePacket wtf")
			case *commands.GetConsensus:
				panic("GetConsensus wtf")
			case *commands.GetConsensus2:
				doc := generateDocument(t, pkiScheme, linkScheme, replicaScheme, sphinxNikeScheme, nil, numDirAuths, numMixNodes, numStorageReplicas, g, mycmd.Epoch)

				docs[mycmd.Epoch], err = ccbor.Marshal((*document)(doc))
				require.NoError(t, err)

				rawcert, err := cert.Sign(auth1IdPrivKey, auth1IdPubKey, docs[mycmd.Epoch], mycmd.Epoch+5)
				require.NoError(t, err)
				rawcert, err = cert.SignMulti(auth2IdPrivKey, auth2IdPubKey, rawcert)
				require.NoError(t, err)
				rawcert, err = cert.SignMulti(auth3IdPrivKey, auth3IdPubKey, rawcert)
				require.NoError(t, err)

				chunkSize := cmds.MaxMessageLenServerToClient
				chunks, err := cpki.Chunk(rawcert, chunkSize)
				require.NoError(t, err)

				resp := &commands.Consensus2{
					Cmds:       cmds,
					ErrorCode:  0,
					ChunkNum:   0,
					ChunkTotal: 1,
					Payload:    chunks[0],
				}
				err = wireConn.SendCommand(resp)
				require.NoError(t, err)
			default:
				break loop
			}
		}

		wireConn.Close()
		_ = conn.Close()
		//require.NoError(t, err)

	}()

	// Initialize callbacks for test - all callbacks are intentionally empty as this test
	// focuses on connection establishment and document retrieval, not event handling
	clientCfg.Callbacks = &config.Callbacks{}
	// Empty callback for test - connection events are not relevant for this test
	clientCfg.Callbacks.OnConnFn = func(err error) {
		// Intentionally empty - connection events not tested here
	}
	// Empty callback for test - document processing is handled elsewhere in test
	clientCfg.Callbacks.OnDocumentFn = func(*cpki.Document) {
		// Intentionally empty - document processing tested separately
	}
	// Empty callback for test - empty message events are not tested here
	clientCfg.Callbacks.OnEmptyFn = func() error {
		// Intentionally empty - empty message events not relevant for connection test
		return nil
	}
	// Empty callback for test - message handling is not the focus of this test
	clientCfg.Callbacks.OnMessageFn = func([]byte) error {
		// Intentionally empty - message handling not tested in this connection test
		return nil
	}
	// Empty callback for test - ACK handling is not tested in this connection test
	clientCfg.Callbacks.OnACKFn = func(*[constants.SURBIDLength]byte, []byte) error {
		// Intentionally empty - ACK handling not relevant for connection establishment test
		return nil
	}

	c, err := New(clientCfg, logbackend)
	require.NoError(t, err)

	time.Sleep(time.Second)

	err = c.Start()
	require.NoError(t, err)

	time.Sleep(time.Second * 3)

	blob, doc := c.CurrentDocument()

	require.NotNil(t, blob)
	require.NotNil(t, doc)

	epoch, _, _ := epochtime.Now()
	require.Equal(t, docs[epoch], blob)

	c.Shutdown()
}

// newTestConnection creates a minimal connection for unit testing channel-based
// methods like sendPacket and GetConsensus without a wire connection.
func newTestConnection(t *testing.T) *connection {
	logbackend, err := log.New("", "DEBUG", false)
	require.NoError(t, err)
	c := &Client{
		logbackend: logbackend,
		cfg: &config.Config{
			Callbacks: &config.Callbacks{},
		},
	}
	return newConnection(c)
}

func TestSendPacketNotConnected(t *testing.T) {
	conn := newTestConnection(t)
	// isConnected defaults to false
	err := conn.sendPacket([]byte("test"))
	require.ErrorIs(t, err, ErrNotConnected)
}

func TestSendPacketShutdown(t *testing.T) {
	conn := newTestConnection(t)
	conn.isConnected = true
	conn.isShutdown = true
	err := conn.sendPacket([]byte("test"))
	require.ErrorIs(t, err, ErrShutdown)
}

func TestSendPacketHaltDuringSend(t *testing.T) {
	conn := newTestConnection(t)
	conn.isConnected = true

	// Nobody reads from sendCh, so it blocks. Halt to unblock.
	go func() {
		time.Sleep(50 * time.Millisecond)
		conn.Halt()
	}()

	err := conn.sendPacket([]byte("test"))
	require.ErrorIs(t, err, ErrShutdown)
}

func TestSendPacketSuccess(t *testing.T) {
	conn := newTestConnection(t)
	conn.isConnected = true

	// Consume from sendCh and call doneFn with nil (success).
	go func() {
		ctx := <-conn.sendCh
		ctx.doneFn(nil)
	}()

	err := conn.sendPacket([]byte("test"))
	require.NoError(t, err)
}

func TestGetConsensusNotConnected(t *testing.T) {
	conn := newTestConnection(t)
	ctx := context.TODO()
	_, err := conn.GetConsensus(ctx, 1)
	require.ErrorIs(t, err, ErrNotConnected)
}

func TestGetConsensusContextCanceled(t *testing.T) {
	conn := newTestConnection(t)
	conn.isConnected = true

	// getConsensusCh has buffer of 1, so fill it to force blocking on the second call.
	conn.getConsensusCh <- &getConsensusCtx{
		doneFn: func(error) {},
	}

	// Now the channel is full. Use an already-cancelled context.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := conn.GetConsensus(ctx, 1)
	require.ErrorIs(t, err, errGetConsensusCanceled)
}

func TestGetConsensusHaltDuringDispatch(t *testing.T) {
	conn := newTestConnection(t)
	conn.isConnected = true

	// Fill the channel so GetConsensus blocks on dispatch.
	conn.getConsensusCh <- &getConsensusCtx{
		doneFn: func(error) {},
	}

	go func() {
		time.Sleep(50 * time.Millisecond)
		conn.Halt()
	}()

	_, err := conn.GetConsensus(context.TODO(), 1)
	require.ErrorIs(t, err, ErrShutdown)
}

func TestOnConnStatusChangeConnected(t *testing.T) {
	conn := newTestConnection(t)
	var called bool
	conn.client.cfg.Callbacks.OnConnFn = func(err error) {
		require.Nil(t, err)
		called = true
	}

	conn.onConnStatusChange(nil)

	conn.isConnectedLock.RLock()
	require.True(t, conn.isConnected)
	conn.isConnectedLock.RUnlock()
	require.True(t, called)
}

func TestOnConnStatusChangeDisconnected(t *testing.T) {
	conn := newTestConnection(t)
	conn.isConnected = true
	var called bool
	someErr := errors.New("connection lost")
	conn.client.cfg.Callbacks.OnConnFn = func(err error) {
		require.Equal(t, someErr, err)
		called = true
	}

	conn.onConnStatusChange(someErr)

	conn.isConnectedLock.RLock()
	require.False(t, conn.isConnected)
	conn.isConnectedLock.RUnlock()
	require.True(t, called)
}

func TestOnConnStatusChangeDrainsSendCh(t *testing.T) {
	conn := newTestConnection(t)
	conn.isConnected = true

	errCh := make(chan error, 1)
	// Pre-load sendCh with a pending send. sendCh is unbuffered, so use a goroutine.
	go func() {
		conn.sendCh <- &connSendCtx{
			pkt: []byte("test"),
			doneFn: func(err error) {
				errCh <- err
			},
		}
	}()
	// Give the goroutine time to block on sendCh.
	time.Sleep(50 * time.Millisecond)

	conn.onConnStatusChange(errors.New("disconnected"))

	select {
	case err := <-errCh:
		require.ErrorIs(t, err, ErrNotConnected)
	case <-time.After(time.Second):
		t.Fatal("doneFn was not called")
	}
}

func TestOnConnStatusChangeDrainsConsensusCh(t *testing.T) {
	conn := newTestConnection(t)
	conn.isConnected = true

	errCh := make(chan error, 1)
	conn.getConsensusCh <- &getConsensusCtx{
		epoch: 1,
		doneFn: func(err error) {
			errCh <- err
		},
	}

	conn.onConnStatusChange(errors.New("disconnected"))

	select {
	case err := <-errCh:
		require.ErrorIs(t, err, ErrNotConnected)
	case <-time.After(time.Second):
		t.Fatal("doneFn was not called")
	}
}

func TestOnConnStatusChangeShutdownNoCallback(t *testing.T) {
	conn := newTestConnection(t)
	conn.isShutdown = true
	conn.client.cfg.Callbacks.OnConnFn = func(err error) {
		t.Fatal("OnConnFn should not be called during shutdown")
	}

	conn.onConnStatusChange(errors.New("some error"))
}

// testGatewayEnv holds the crypto keys and geometry needed for mock gateway tests.
type testGatewayEnv struct {
	pkiScheme      sign.Scheme
	linkScheme     kem.Scheme
	nikeScheme     nike.Scheme
	geo            *geo.Geometry
	authKeys       [3]struct {
		pub  sign.PublicKey
		priv sign.PrivateKey
	}
}

func newTestGatewayEnv(t *testing.T) *testGatewayEnv {
	env := &testGatewayEnv{
		pkiScheme:  signSchemes.ByName("ed25519"),
		linkScheme: kemSchemes.ByName("x25519"),
		nikeScheme: schemes.ByName("x25519"),
	}
	env.geo = geo.GeometryFromUserForwardPayloadLength(env.nikeScheme, 2000, false, 5)
	for i := range env.authKeys {
		pub, priv, err := env.pkiScheme.GenerateKey()
		require.NoError(t, err)
		env.authKeys[i].pub = pub
		env.authKeys[i].priv = priv
	}
	return env
}

// sendValidDocument sends a properly signed and chunked Consensus2 document.
func (env *testGatewayEnv) sendValidDocument(t *testing.T, wireConn *wire.Session, cmds *commands.Commands, epoch uint64) {
	replicaScheme := schemes.ByName("x25519")
	doc := generateDocument(t, env.pkiScheme, env.linkScheme, replicaScheme, env.nikeScheme, nil, 3, 3, 0, env.geo, epoch)
	docBytes, err := ccbor.Marshal((*document)(doc))
	require.NoError(t, err)
	rawcert, err := cert.Sign(env.authKeys[0].priv, env.authKeys[0].pub, docBytes, epoch+5)
	require.NoError(t, err)
	rawcert, err = cert.SignMulti(env.authKeys[1].priv, env.authKeys[1].pub, rawcert)
	require.NoError(t, err)
	rawcert, err = cert.SignMulti(env.authKeys[2].priv, env.authKeys[2].pub, rawcert)
	require.NoError(t, err)

	chunkSize := cmds.MaxMessageLenServerToClient
	chunks, err := cpki.Chunk(rawcert, chunkSize)
	require.NoError(t, err)
	for i, chunk := range chunks {
		resp := &commands.Consensus2{
			Cmds:       cmds,
			ErrorCode:  commands.ConsensusOk,
			ChunkNum:   uint32(i),
			ChunkTotal: uint32(len(chunks)),
			Payload:    chunk,
		}
		err = wireConn.SendCommand(resp)
		require.NoError(t, err)
	}
}

// setupTestGatewayFull creates a mock gateway with a general command handler.
// The handler receives every command and the wire session to send responses.
func setupTestGatewayFull(t *testing.T, gwAddr string, env *testGatewayEnv, handler func(t *testing.T, wireConn *wire.Session, cmds *commands.Commands, cmd commands.Command) bool) *config.Config {
	gwlinkPubKey, gwlinkPrivKey, err := env.linkScheme.GenerateKeyPair()
	require.NoError(t, err)

	authlinkPubKey, _, err := env.linkScheme.GenerateKeyPair()
	require.NoError(t, err)

	auth := &authenticator{
		log:     func() *logging.Logger { lb, _ := log.New("", "DEBUG", false); return lb.GetLogger("auth") }(),
		pubkey:  gwlinkPubKey,
		privkey: gwlinkPrivKey,
	}

	idPubKey, _, err := env.pkiScheme.GenerateKey()
	require.NoError(t, err)
	id := hash.Sum256From(idPubKey)

	pigeonholeGeometry, err := pigeonholeGeo.NewGeometryFromSphinx(env.geo, env.nikeScheme)
	require.NoError(t, err)

	clientCfg := &config.Config{
		ListenNetwork:      "tcp",
		ListenAddress:      "127.0.0.1:0",
		PKISignatureScheme: "ed25519",
		WireKEMScheme:      "x25519",
		SphinxGeometry:     env.geo,
		PigeonholeGeometry: pigeonholeGeometry,
		Logging:            &config.Logging{Level: "DEBUG"},
		UpstreamProxy:      &config.UpstreamProxy{},
		Debug:              &config.Debug{EnableTimeSync: true},
		PinnedGateways: &config.Gateways{
			Gateways: []*config.Gateway{{
				WireKEMScheme:      "x25519",
				Name:               "gateway",
				IdentityKey:        idPubKey,
				LinkKey:            gwlinkPubKey,
				PKISignatureScheme: "ed25519",
				Addresses:          []string{gwAddr},
			}},
		},
		VotingAuthority: &config.VotingAuthority{
			Peers: []*vServerConfig.Authority{
				{Identifier: "auth1", IdentityPublicKey: env.authKeys[0].pub, PKISignatureScheme: "ed25519", LinkPublicKey: authlinkPubKey, WireKEMScheme: "x25519", Addresses: []string{"tcp://127.0.0.1:1301"}},
				{Identifier: "auth2", IdentityPublicKey: env.authKeys[1].pub, PKISignatureScheme: "ed25519", LinkPublicKey: authlinkPubKey, WireKEMScheme: "x25519", Addresses: []string{"tcp://127.0.0.1:1302"}},
				{Identifier: "auth3", IdentityPublicKey: env.authKeys[2].pub, PKISignatureScheme: "ed25519", LinkPublicKey: authlinkPubKey, WireKEMScheme: "x25519", Addresses: []string{"tcp://127.0.0.1:1303"}},
			},
		},
	}

	go func() {
		u, err := url.Parse(gwAddr)
		require.NoError(t, err)
		l, err := net.Listen("tcp", u.Host)
		require.NoError(t, err)
		defer l.Close()

		conn, err := l.Accept()
		require.NoError(t, err)

		cfg := &wire.SessionConfig{
			KEMScheme:          env.linkScheme,
			PKISignatureScheme: env.pkiScheme,
			Geometry:           env.geo,
			Authenticator:      auth,
			AdditionalData:     id[:],
			AuthenticationKey:  gwlinkPrivKey,
			RandomReader:       rand.Reader,
		}
		wireConn, err := wire.NewSession(cfg, false)
		require.NoError(t, err)
		err = wireConn.Initialize(conn)
		require.NoError(t, err)

		cmds := commands.NewMixnetCommands(env.geo)

		for {
			cmd, err := wireConn.RecvCommand()
			if err != nil || cmd == nil {
				return
			}
			// Return false from handler to stop the loop.
			if !handler(t, wireConn, cmds, cmd) {
				return
			}
		}
	}()

	return clientCfg
}

func TestOnWireConnMultiChunkConsensus(t *testing.T) {
	env := newTestGatewayEnv(t)
	gwAddr := "tcp://127.0.0.1:12350"

	clientCfg := setupTestGatewayFull(t, gwAddr, env, func(t *testing.T, wireConn *wire.Session, cmds *commands.Commands, cmd commands.Command) bool {
		switch mycmd := cmd.(type) {
		case *commands.RetrieveMessage:
			resp := &commands.MessageEmpty{Cmds: cmds, Sequence: mycmd.Sequence}
			wireConn.SendCommand(resp)
		case *commands.GetConsensus2:
			// Send a valid multi-chunk document.
			env.sendValidDocument(t, wireConn, cmds, mycmd.Epoch)
		}
		return true
	})
	setupClientCallbacks(clientCfg)

	logbackend, err := log.New("", "DEBUG", false)
	require.NoError(t, err)
	c, err := New(clientCfg, logbackend)
	require.NoError(t, err)

	time.Sleep(time.Second)
	err = c.Start()
	require.NoError(t, err)
	time.Sleep(time.Second * 3)

	_, doc := c.CurrentDocument()
	require.NotNil(t, doc, "client should have assembled a multi-chunk document")

	c.Shutdown()
}

func TestOnWireConnDisconnectCommand(t *testing.T) {
	env := newTestGatewayEnv(t)
	gwAddr := "tcp://127.0.0.1:12351"
	gotConsensus := false

	clientCfg := setupTestGatewayFull(t, gwAddr, env, func(t *testing.T, wireConn *wire.Session, cmds *commands.Commands, cmd commands.Command) bool {
		switch mycmd := cmd.(type) {
		case *commands.RetrieveMessage:
			resp := &commands.MessageEmpty{Cmds: cmds, Sequence: mycmd.Sequence}
			wireConn.SendCommand(resp)
		case *commands.GetConsensus2:
			if !gotConsensus {
				gotConsensus = true
				env.sendValidDocument(t, wireConn, cmds, mycmd.Epoch)
				return true
			}
			// After first doc, send Disconnect.
			wireConn.SendCommand(&commands.Disconnect{})
			return false
		}
		return true
	})
	setupClientCallbacks(clientCfg)

	logbackend, err := log.New("", "DEBUG", false)
	require.NoError(t, err)
	c, err := New(clientCfg, logbackend)
	require.NoError(t, err)

	time.Sleep(time.Second)
	err = c.Start()
	require.NoError(t, err)
	time.Sleep(time.Second * 3)

	// Client should have gotten the first document before disconnect.
	_, doc := c.CurrentDocument()
	require.NotNil(t, doc)

	c.Shutdown()
}

func TestOnWireConnMessageACKCallback(t *testing.T) {
	env := newTestGatewayEnv(t)
	gwAddr := "tcp://127.0.0.1:12352"
	sentACK := false

	ackCh := make(chan []byte, 1)

	clientCfg := setupTestGatewayFull(t, gwAddr, env, func(t *testing.T, wireConn *wire.Session, cmds *commands.Commands, cmd commands.Command) bool {
		switch mycmd := cmd.(type) {
		case *commands.RetrieveMessage:
			if !sentACK {
				sentACK = true
				// Send a MessageACK instead of MessageEmpty.
				var surbID [constants.SURBIDLength]byte
				copy(surbID[:], []byte("test-surb-id-xxx"))
				resp := &commands.MessageACK{
					Geo:           env.geo,
					Cmds:          cmds,
					QueueSizeHint: 0,
					Sequence:      mycmd.Sequence,
					ID:            surbID,
					Payload:       make([]byte, env.geo.PayloadTagLength+env.geo.ForwardPayloadLength),
				}
				wireConn.SendCommand(resp)
			} else {
				resp := &commands.MessageEmpty{Cmds: cmds, Sequence: mycmd.Sequence}
				wireConn.SendCommand(resp)
			}
		case *commands.GetConsensus2:
			env.sendValidDocument(t, wireConn, cmds, mycmd.Epoch)
		}
		return true
	})

	clientCfg.Callbacks = &config.Callbacks{
		OnConnFn:     func(error) {},
		OnDocumentFn: func(*cpki.Document) {},
		OnEmptyFn:    func() error { return nil },
		OnMessageFn:  func([]byte) error { return nil },
		OnACKFn: func(id *[constants.SURBIDLength]byte, payload []byte) error {
			ackCh <- id[:]
			return nil
		},
	}

	logbackend, err := log.New("", "DEBUG", false)
	require.NoError(t, err)
	c, err := New(clientCfg, logbackend)
	require.NoError(t, err)

	time.Sleep(time.Second)
	err = c.Start()
	require.NoError(t, err)

	select {
	case id := <-ackCh:
		require.Equal(t, []byte("test-surb-id-xxx"), id[:constants.SURBIDLength])
	case <-time.After(10 * time.Second):
		t.Fatal("OnACKFn was not called")
	}

	c.Shutdown()
}
