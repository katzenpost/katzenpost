// SPDX-FileCopyrightText: © 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"crypto/hmac"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/kem"
	"github.com/katzenpost/hpqc/kem/mkem"
	pemkem "github.com/katzenpost/hpqc/kem/pem"
	kemSchemes "github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/hpqc/sign"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"

	aconfig "github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/pki"
	sConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/core/wire/commands"
	"github.com/katzenpost/katzenpost/courier/server/config"
)

var (
	ccbor cbor.EncMode
)

// document contains fields from Document but not the encoding.BinaryMarshaler methods
type document pki.Document

type mockPKI struct {
	t                *testing.T
	pkiScheme        sign.Scheme
	linkScheme       kem.Scheme
	replicaScheme    nike.Scheme
	sphinxNikeScheme nike.Scheme
	geo              *geo.Geometry

	docs map[uint64]*pki.Document

	replica1IdPubKey    sign.PublicKey
	replica1IdPrivKey   sign.PrivateKey
	replica1LinkPubKey  kem.PublicKey
	replica1LinkPrivKey kem.PrivateKey
	replica1PubKey      nike.PublicKey
	replica1PrivKey     nike.PrivateKey
	replica1Addresses   map[string][]string

	replica2IdPubKey    sign.PublicKey
	replica2IdPrivKey   sign.PrivateKey
	replica2LinkPubKey  kem.PublicKey
	replica2LinkPrivKey kem.PrivateKey
	replica2PubKey      nike.PublicKey
	replica2PrivKey     nike.PrivateKey
	replica2Addresses   map[string][]string
}

func newMockPKI(t *testing.T,
	pkiScheme sign.Scheme,
	linkScheme kem.Scheme,
	replicaScheme nike.Scheme,
	sphinxNikeScheme nike.Scheme,
	geo *geo.Geometry) *mockPKI {

	return &mockPKI{
		t:                t,
		docs:             make(map[uint64]*pki.Document),
		pkiScheme:        pkiScheme,
		linkScheme:       linkScheme,
		replicaScheme:    replicaScheme,
		sphinxNikeScheme: sphinxNikeScheme,
		geo:              geo,
	}
}

func (m *mockPKI) replicaID(replicaNum int) (sign.PublicKey, sign.PrivateKey) {
	switch replicaNum {
	case 0:
		return m.replica1IdPubKey, m.replica1IdPrivKey
	case 1:
		return m.replica2IdPubKey, m.replica2IdPrivKey
	default:
		panic("wtf")
	}
}

func (m *mockPKI) replicaLink(replicaNum int) (kem.PublicKey, kem.PrivateKey) {
	switch replicaNum {
	case 0:
		return m.replica1LinkPubKey, m.replica1LinkPrivKey
	case 1:
		return m.replica2LinkPubKey, m.replica2LinkPrivKey
	default:
		panic("wtf")
	}
}

func (m *mockPKI) replicaKeys(replicaNum int) (nike.PublicKey, nike.PrivateKey) {
	switch replicaNum {
	case 0:
		return m.replica1PubKey, m.replica1PrivKey
	case 1:
		return m.replica2PubKey, m.replica2PrivKey
	default:
		panic("wtf")
	}
}

func (m *mockPKI) IsPeerValid(cred *wire.PeerCredentials) bool {
	return true
}

func (m *mockPKI) spawnReplica(replicaNum int) {
	doc := m.PKIDocument()
	replicaDesc := doc.StorageReplicas[replicaNum]
	addr := replicaDesc.Addresses["tcp4"][0]
	u, err := url.Parse(addr)
	require.NoError(m.t, err)

	m.t.Logf("listening on %s", u.Host)
	l, err := net.Listen("tcp", u.Host)
	require.NoError(m.t, err)

	conn, err := l.Accept()
	require.NoError(m.t, err)

	_, linkprivkey := m.replicaLink(replicaNum)
	idpubkey, _ := m.replicaID(replicaNum)
	id := hash.Sum256From(idpubkey)

	cfg := &wire.SessionConfig{
		KEMScheme:          m.linkScheme,
		PKISignatureScheme: m.pkiScheme,
		Geometry:           m.geo,
		Authenticator:      m,
		AdditionalData:     id[:],
		AuthenticationKey:  linkprivkey,
		RandomReader:       rand.Reader,
	}
	wireConn, err := wire.NewStorageReplicaSession(cfg, m.replicaScheme, false)
	require.NoError(m.t, err)

	err = wireConn.Initialize(conn)
	require.NoError(m.t, err)

	t := m.t
loop:
	for {
		t.Log("BEFORE RecvCommand")
		cmd, _ := wireConn.RecvCommand()
		//require.NoError(t, _)

		if cmd == nil {
			return
		}

		switch mycmd := cmd.(type) {
		case *commands.NoOp:
			t.Log("-- NoOp")
		case *commands.Disconnect:
			t.Log("-- Disconnect")
			break loop
		case *commands.ReplicaMessage:
			t.Log("-- ReplicaMessage")
			resp := &commands.ReplicaMessageReply{
				Cmds: commands.NewStorageReplicaCommands(m.geo, m.replicaScheme),

				ErrorCode:     0,
				EnvelopeHash:  &[32]byte{},
				EnvelopeReply: []byte{},
			}
			_ = wireConn.SendCommand(resp)
		case *commands.ReplicaRead:
			t.Log("-- ReplicaRead")
			resp := &commands.ReplicaReadReply{
				Cmds: commands.NewStorageReplicaCommands(m.geo, m.replicaScheme),
				Geo:  m.geo,

				ErrorCode: 0,
				BoxID:     &[32]byte{},
				Signature: &[32]byte{},
				Payload:   []byte{},
			}
			_ = wireConn.SendCommand(resp)
		case *commands.ReplicaWrite:
			t.Log("-- ReplicaWrite")
			resp := &commands.ReplicaWriteReply{
				Cmds: commands.NewStorageReplicaCommands(m.geo, m.replicaScheme),

				ErrorCode: 0,
			}
			_ = wireConn.SendCommand(resp)
		default:
			t.Logf("-- invalid wire command: %v", mycmd)
			break loop
		}
	}

	wireConn.Close()
	_ = conn.Close()
	//require.NoError(t, err)
}

func (m *mockPKI) generateReplicaDescriptors(t *testing.T, epoch uint64) (*pki.ReplicaDescriptor, *pki.ReplicaDescriptor) {
	var err error

	replica1name := "replica1"
	m.replica1IdPubKey, m.replica1IdPrivKey, err = m.pkiScheme.GenerateKey()
	require.NoError(t, err)

	idkey1, err := m.replica1IdPubKey.MarshalBinary()
	require.NoError(t, err)

	m.replica1LinkPubKey, m.replica1LinkPrivKey, err = m.linkScheme.GenerateKeyPair()
	linkKey1, err := m.replica1LinkPubKey.MarshalBinary()
	require.NoError(t, err)

	envelopeKeys1 := make(map[uint64][]byte)
	m.replica1PubKey, m.replica1PrivKey, err = m.replicaScheme.GenerateKeyPair()
	require.NoError(t, err)
	envelopeKeys1[epoch] = m.replica1PubKey.Bytes()

	m.replica1Addresses = make(map[string][]string)
	m.replica1Addresses["tcp4"] = []string{"tcp://127.0.0.1:34566"}

	desc1 := &pki.ReplicaDescriptor{
		Name:         replica1name,
		Epoch:        epoch,
		IdentityKey:  idkey1,
		LinkKey:      linkKey1,
		EnvelopeKeys: envelopeKeys1,
		Addresses:    m.replica1Addresses,
	}

	replica2name := "replica2"
	m.replica2IdPubKey, m.replica2IdPrivKey, err = m.pkiScheme.GenerateKey()
	require.NoError(t, err)

	idkey2, err := m.replica2IdPubKey.MarshalBinary()
	require.NoError(t, err)

	m.replica2LinkPubKey, m.replica2LinkPrivKey, err = m.linkScheme.GenerateKeyPair()
	linkKey2, err := m.replica2LinkPubKey.MarshalBinary()
	require.NoError(t, err)

	envelopeKeys2 := make(map[uint64][]byte)
	m.replica2PubKey, m.replica2PrivKey, err = m.replicaScheme.GenerateKeyPair()
	require.NoError(t, err)
	envelopeKeys2[epoch] = m.replica2PubKey.Bytes()

	m.replica2Addresses = make(map[string][]string)
	m.replica2Addresses["tcp4"] = []string{"tcp://127.0.0.1:34567"}

	desc2 := &pki.ReplicaDescriptor{
		Name:         replica2name,
		Epoch:        epoch,
		IdentityKey:  idkey2,
		LinkKey:      linkKey2,
		EnvelopeKeys: envelopeKeys2,
		Addresses:    m.replica2Addresses,
	}
	return desc1, desc2
}

func (m *mockPKI) generateDocument(t *testing.T, numDirAuths, numMixNodes, numStorageReplicas int, geo *geo.Geometry, epoch uint64) *pki.Document {
	srv := make([]byte, 32)
	_, err := rand.Reader.Read(srv)
	require.NoError(t, err)
	oldhashes := [][]byte{srv, srv}

	replica1, replica2 := m.generateReplicaDescriptors(t, epoch)

	doc := &pki.Document{
		Epoch:              epoch,
		GenesisEpoch:       epoch,
		SendRatePerMinute:  0,
		Mu:                 1,
		MuMaxDelay:         1,
		LambdaP:            1,
		LambdaPMaxDelay:    1,
		LambdaL:            1,
		LambdaLMaxDelay:    1,
		LambdaD:            1,
		LambdaDMaxDelay:    1,
		LambdaM:            1,
		LambdaMMaxDelay:    1,
		LambdaG:            1,
		LambdaGMaxDelay:    1,
		StorageReplicas:    []*pki.ReplicaDescriptor{replica1, replica2},
		SharedRandomValue:  srv,
		PriorSharedRandom:  oldhashes,
		SphinxGeometryHash: geo.Hash(),
		PKISignatureScheme: m.pkiScheme.Name(),
		Version:            pki.DocumentVersion,
	}
	m.docs[epoch] = doc
	return doc
}

func (m *mockPKI) AuthenticateReplicaConnection(c *wire.PeerCredentials) (*pki.ReplicaDescriptor, bool) {
	if len(c.AdditionalData) != sConstants.NodeIDLength {
		m.t.Logf("AuthenticateConnection: '%x' AD not an IdentityKey?.", c.AdditionalData)
		return nil, false
	}
	doc := m.PKIDocument()
	var nodeID [sConstants.NodeIDLength]byte
	copy(nodeID[:], c.AdditionalData)
	m.t.Logf("PKI DOC %v", doc)
	m.t.Logf("NODE ID %x", nodeID)
	replicaDesc, err := doc.GetReplicaNodeByKeyHash(&nodeID)
	require.NoError(m.t, err)

	blob, err := c.PublicKey.MarshalBinary()
	require.NoError(m.t, err)

	if !hmac.Equal(replicaDesc.LinkKey, blob) {
		return nil, false
	}
	return replicaDesc, true
}

func (m *mockPKI) PKIDocument() *pki.Document {
	epoch, _, _ := epochtime.Now()
	doc, ok := m.docs[epoch]
	if !ok {
		doc = m.generateDocument(m.t, 3, 3, 3, m.geo, epoch)
		return doc
	} else {
		return doc
	}
}

func (m *mockPKI) ReplicasCopy() map[[32]byte]*pki.ReplicaDescriptor {
	doc := m.PKIDocument()
	replicas1 := doc.StorageReplicas[0]
	replicas2 := doc.StorageReplicas[1]
	id1 := hash.Sum256(replicas1.IdentityKey)
	id2 := hash.Sum256(replicas2.IdentityKey)
	replicas := make(map[[32]byte]*pki.ReplicaDescriptor)
	replicas[id1] = replicas1
	replicas[id2] = replicas2
	return replicas
}

func TestConnector(t *testing.T) {
	datadir, err := os.MkdirTemp("", "courier_connector_test_datadir")
	require.NoError(t, err)

	serviceNodeDatadir, err := os.MkdirTemp("", "courier_connector_test_servicenode_datadir")
	require.NoError(t, err)

	mkemNikeScheme := schemes.ByName("x25519")
	mkemScheme := mkem.NewScheme(mkemNikeScheme)

	nikeScheme := schemes.ByName("x25519")
	g := geo.GeometryFromUserForwardPayloadLength(nikeScheme, 2000, false, 5)

	WireKEMSchemeName := "x25519"
	linkScheme := kemSchemes.ByName(WireKEMSchemeName)

	linkpubkey, linkprivkey, err := linkScheme.GenerateKeyPair()
	require.NoError(t, err)

	linkPrivateKeyFile := filepath.Join(serviceNodeDatadir, "link.private.pem")
	linkPublicKeyFile := filepath.Join(serviceNodeDatadir, "link.public.pem")
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
		WireKEMScheme:      WireKEMSchemeName,
		DataDir:            datadir,
		ServiceNodeDataDir: serviceNodeDatadir,
		SphinxGeometry:     g,
		ConnectTimeout:     config.DefaultConnectTimeout,
		HandshakeTimeout:   config.DefaultHandshakeTimeout,
		ReauthInterval:     config.DefaultReauthInterval,
	}

	m := newMockPKI(t, pkiScheme, linkScheme, mkemNikeScheme, nikeScheme, g)

	go m.spawnReplica(0)
	go m.spawnReplica(1)

	time.Sleep(time.Second * 3)

	epoch, _, _ := epochtime.Now()
	numStorageReplicas := 2
	numMixNodes := 3
	numDirAuths := 3

	pkiFactory := func(s *Server) {
		s.pki = m
	}

	server, err := New(cfg, pkiFactory)
	require.NoError(t, err)

	server.pki.(*mockPKI).generateDocument(m.t, numDirAuths, numMixNodes, numStorageReplicas, m.geo, epoch)

	connector := newConnector(server)
	connector.ForceUpdate()

	time.Sleep(time.Second * 3)
	dest := uint8(0)

	mkemPubkey, _, err := mkemScheme.GenerateKeyPair()
	require.NoError(t, err)

	replica1Pub, _ := m.replicaKeys(0)
	replica2Pub, _ := m.replicaKeys(1)

	// client creates a replica command
	boxid := &[32]byte{}
	_, err = rand.Reader.Read(boxid[:])
	require.NoError(t, err)
	sig := &[32]byte{}
	_, err = rand.Reader.Read(boxid[:])
	require.NoError(t, err)
	payload := []byte("hello")

	replicaWrite := commands.ReplicaWrite{
		Cmds: commands.NewStorageReplicaCommands(g, nikeScheme),

		BoxID:     boxid,
		Signature: sig,
		Payload:   payload,
	}

	_, envelopeRaw := mkemScheme.Encapsulate([]nike.PublicKey{replica1Pub, replica2Pub}, replicaWrite.ToBytes())
	envelope1, err := mkem.CiphertextFromBytes(mkemScheme, envelopeRaw)
	require.NoError(t, err)
	dek := &[32]byte{}
	copy(dek[:], envelope1.DEKCiphertexts[0])
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
