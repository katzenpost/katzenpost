// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client2

import (
	"fmt"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/kem"
	kemSchemes "github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/hpqc/rand"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"

	vServerConfig "github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/client2/config"
	"github.com/katzenpost/katzenpost/core/log"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/core/wire/commands"
)

type authenticator struct {
	log *logging.Logger

	pubkey  kem.PublicKey
	privkey kem.PrivateKey
}

func (a *authenticator) IsPeerValid(creds *wire.PeerCredentials) bool {
	a.log.Debug(" --- IsPeerValid --- ")
	return true // XXX
}

func TestConnection(t *testing.T) {

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

	nikeScheme := schemes.ByName("x25519")
	g := geo.GeometryFromUserForwardPayloadLength(nikeScheme, 2000, false, 5)

	gwAddr := "tcp://127.0.0.1:1234"

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

	loop:
		for {
			t.Log("BEFORE RecvCommand")
			cmd, err := wireConn.RecvCommand()
			require.NoError(t, err)

			switch cmd.(type) {
			case *commands.NoOp:
				t.Log("-- NoOp")
			case *commands.Disconnect:
				t.Log("-- Disconnect")
				break loop
			case *commands.SendPacket:
				t.Log("-- SendPacket")
			case *commands.RetrieveMessage:
				t.Log("-- RetrieveMessage")
			case *commands.SendRetrievePacket:
				t.Log("-- SendRetrievePacket")
			case *commands.GetConsensus2:
				t.Log("-- GetConsensus2")
				resp := &commands.Consensus2{
					Cmds: commands.NewMixnetCommands(g),

					ErrorCode:  0,
					ChunkNum:   0,
					ChunkTotal: 3,
					Payload:    []byte{},
				}
				wireConn.SendCommand(resp)
			case *commands.GetConsensus:
				t.Log("-- GetConsensus")
			default:
				t.Log("-- invalid wire command")
				break loop
			}
		}

		wireConn.Close()
		err = conn.Close()
		require.NoError(t, err)

	}()

	cfg := &config.Config{
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
					Addresses:          []string{"tcp://127.0.0.1:1224"},
				},
			},
		},
		Callbacks:          nil,
		PreferedTransports: nil,
	}

	cfg.Callbacks = &config.Callbacks{}
	cfg.Callbacks.OnConnFn = func(err error) {
		fmt.Println("OnConnFn")
		return
	}
	cfg.Callbacks.OnDocumentFn = func(*cpki.Document) {
		fmt.Println("OnDocumentFn")
		return
	}
	cfg.Callbacks.OnEmptyFn = func() error {
		fmt.Println("OnEmptyFn")
		return nil
	}
	cfg.Callbacks.OnMessageFn = func([]byte) error {
		fmt.Println("OnMessageFn")
		return nil
	}
	cfg.Callbacks.OnACKFn = func(*[constants.SURBIDLength]byte, []byte) error {
		fmt.Println("OnACKFn")
		return nil
	}

	c, err := New(cfg, logbackend)
	require.NoError(t, err)

	time.Sleep(time.Second)

	err = c.Start()
	require.NoError(t, err)

	time.Sleep(time.Second * 3)

	c.Shutdown()
}
