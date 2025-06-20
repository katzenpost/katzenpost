//go:build skiptest

// SPDX-FileCopyrightText: © 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"crypto/hmac"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/kem/mkem"
	pemkem "github.com/katzenpost/hpqc/kem/pem"
	kemSchemes "github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/hpqc/rand"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"

	aconfig "github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/wire/commands"
	"github.com/katzenpost/katzenpost/courier/server/config"
)

var (
	ccbor cbor.EncMode
)

func TestConnector(t *testing.T) {
	datadir, err := os.MkdirTemp("", "courier_connector_test_datadir")
	require.NoError(t, err)

	mkemNikeScheme := schemes.ByName("x25519")
	mkemScheme := mkem.NewScheme(mkemNikeScheme)

	nikeSchemeName := "x25519"
	nikeScheme := schemes.ByName(nikeSchemeName)
	g := geo.GeometryFromUserForwardPayloadLength(nikeScheme, 2000, false, 5)

	WireKEMSchemeName := "x25519"
	linkScheme := kemSchemes.ByName(WireKEMSchemeName)

	linkpubkey, linkprivkey, err := linkScheme.GenerateKeyPair()
	require.NoError(t, err)

	linkPrivateKeyFile := filepath.Join(datadir, "link.private.pem")
	linkPublicKeyFile := filepath.Join(datadir, "link.public.pem")
	err = pemkem.PrivateKeyToFile(linkPrivateKeyFile, linkprivkey)
	err = pemkem.PublicKeyToFile(linkPublicKeyFile, linkpubkey)

	pkiSchemeName := "ed25519"
	pkiScheme := signSchemes.ByName(pkiSchemeName)

	auth1IdPubKey, _, err := pkiScheme.GenerateKey()
	require.NoError(t, err)

	authlinkPubKey, _, err := linkScheme.GenerateKeyPair()
	require.NoError(t, err)

	cfg := &config.Config{
		PKI: &config.PKI{
			Voting: &config.Voting{
				Authorities: []*aconfig.Authority{
					&aconfig.Authority{
						Identifier:         "auth1",
						IdentityPublicKey:  auth1IdPubKey,
						PKISignatureScheme: pkiSchemeName,
						LinkPublicKey:      authlinkPubKey,
						WireKEMScheme:      WireKEMSchemeName,
						Addresses:          []string{"tcp://127.0.0.1:1224"},
					},
				},
			},
		},
		Logging: &config.Logging{
			Disable: false,
			File:    "",
			Level:   "DEBUG",
		},
		PKIScheme:        pkiSchemeName,
		EnvelopeScheme:   nikeSchemeName,
		WireKEMScheme:    WireKEMSchemeName,
		DataDir:          datadir,
		SphinxGeometry:   g,
		ConnectTimeout:   config.DefaultConnectTimeout,
		HandshakeTimeout: config.DefaultHandshakeTimeout,
		ReauthInterval:   config.DefaultReauthInterval,
	}

	m := newMockPKI(t, pkiScheme, linkScheme, mkemNikeScheme, nikeScheme, g)

	go m.spawnReplica(0)
	go m.spawnReplica(1)

	time.Sleep(time.Second * 3)

	epoch, _, _ := epochtime.Now()
	numStorageReplicas := 2
	numMixNodes := 3
	numDirAuths := 3

	server, err := New(cfg, pkiClient)
	require.NoError(t, err)

	server.PKI.(*mockPKI).generateDocument(m.t, numDirAuths, numMixNodes, numStorageReplicas, m.geo, epoch)

	connector := newConnector(server)
	connector.ForceUpdate()

	time.Sleep(time.Second * 3)
	dest := uint8(0)

	mkemPubkey, _, err := mkemScheme.GenerateKeyPair()
	require.NoError(t, err)

	replica1Pub, _ := m.replicaKeys(0)
	replica2Pub, _ := m.replicaKeys(1)

	// client creates a replica command
	boxid := &[bacap.BoxIDSize]byte{}
	_, err = rand.Reader.Read(boxid[:])
	require.NoError(t, err)
	sig := &[64]byte{}
	_, err = rand.Reader.Read(boxid[:])
	require.NoError(t, err)
	payload := []byte("hello")

	replicaWrite := commands.ReplicaWrite{
		Cmds: commands.NewStorageReplicaCommands(g, nikeScheme),

		BoxID:     boxid,
		Signature: sig,
		Payload:   payload,
	}

	_, envelope1 := mkemScheme.Encapsulate([]nike.PublicKey{replica1Pub, replica2Pub}, replicaWrite.ToBytes())
	dek := &[mkem.DEKSize]byte{}
	copy(dek[:], envelope1.DEKCiphertexts[0][:])
	mesg := &commands.ReplicaMessage{
		Cmds:   commands.NewStorageReplicaCommands(g, nikeScheme),
		Geo:    g,
		Scheme: nikeScheme,

		SenderEPubKey: mkemPubkey.Bytes(),
		DEK:           dek,
		Ciphertext:    envelope1.Envelope,
	}
	connector.DispatchMessage(dest, mesg)

	time.Sleep(time.Second * 3)
}
