// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client2

import (
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
)

// document contains fields from Document but not the encoding.BinaryMarshaler methods
type document cpki.Document

type mixKeys struct {
	idpubkey  []sign.PublicKey
	idprivkey []sign.PrivateKey

	pubkeys  []nike.PublicKey
	privkeys []nike.PrivateKey
}

func generateDescriptor(t *testing.T, pkiScheme sign.Scheme, linkScheme kem.Scheme, sphinxNikeScheme nike.Scheme, sphinxKemScheme kem.Scheme) *cpki.MixDescriptor {
	idkey := make([]byte, pkiScheme.PublicKeySize())
	_, err := rand.Reader.Read(idkey)
	require.NoError(t, err)

	linkkey := make([]byte, linkScheme.PublicKeySize())
	_, err = rand.Reader.Read(linkkey)
	require.NoError(t, err)

	var mixkey0 []byte
	var mixkey1 []byte

	if sphinxNikeScheme == nil {
		mixkey0 = make([]byte, sphinxKemScheme.PublicKeySize())
		mixkey1 = make([]byte, sphinxKemScheme.PublicKeySize())
	} else {
		mixkey0 = make([]byte, sphinxNikeScheme.PublicKeySize())
		mixkey1 = make([]byte, sphinxNikeScheme.PublicKeySize())
	}

	_, err = rand.Reader.Read(mixkey0)
	require.NoError(t, err)
	_, err = rand.Reader.Read(mixkey1)
	require.NoError(t, err)

	return &cpki.MixDescriptor{
		Name:        "fake mix node name",
		IdentityKey: idkey,
		LinkKey:     linkkey,
		MixKeys:     map[uint64][]byte{0: mixkey0, 1: mixkey1},
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

	clientCfg := &config.Config{
		ListenNetwork:      "tcp",
		ListenAddress:      "127.0.0.1:63445",
		PKISignatureScheme: "ed25519",
		WireKEMScheme:      "x25519",
		SphinxGeometry:     g,
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

	clientCfg.Callbacks = &config.Callbacks{}
	clientCfg.Callbacks.OnConnFn = func(err error) {
		return
	}
	clientCfg.Callbacks.OnDocumentFn = func(*cpki.Document) {
		return
	}
	clientCfg.Callbacks.OnEmptyFn = func() error {
		return nil
	}
	clientCfg.Callbacks.OnMessageFn = func([]byte) error {
		return nil
	}
	clientCfg.Callbacks.OnACKFn = func(*[constants.SURBIDLength]byte, []byte) error {
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
