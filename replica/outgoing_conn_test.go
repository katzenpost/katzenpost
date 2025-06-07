// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"
	kemschemes "github.com/katzenpost/hpqc/kem/schemes"
	nikeschemes "github.com/katzenpost/hpqc/nike/schemes"
	ecdh "github.com/katzenpost/hpqc/nike/x25519"
	"github.com/katzenpost/hpqc/rand"
	signschemes "github.com/katzenpost/hpqc/sign/schemes"

	authconfig "github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/replica/common"
	"github.com/katzenpost/katzenpost/replica/config"
)

func TestOutgoingConn(t *testing.T) {
	logBackend, err := log.New("", "DEBUG", false)
	require.NoError(t, err)

	dname, err := os.MkdirTemp("", fmt.Sprintf("replica.testState %d", os.Getpid()))
	require.NoError(t, err)
	defer os.RemoveAll(dname)

	nike := ecdh.Scheme(rand.Reader)
	forwardPayloadLength := 1234
	nrHops := 5
	geo := geo.GeometryFromUserForwardPayloadLength(nike, forwardPayloadLength, true, nrHops)
	require.NotNil(t, geo)

	pkiScheme := signschemes.ByName("ed25519")
	linkScheme := kemschemes.ByName("x25519")
	replicaScheme := nikeschemes.ByName("x25519")

	idpubkey, _, err := pkiScheme.GenerateKey()
	require.NoError(t, err)

	dstReplicaDesc := generateReplica(t, pkiScheme, linkScheme, replicaScheme)
	linkpubkey, err := linkScheme.UnmarshalBinaryPublicKey(dstReplicaDesc.LinkKey)
	require.NoError(t, err)

	pk, _, err := pkiScheme.GenerateKey()
	require.NoError(t, err)

	cfg := &config.Config{
		PKI: &config.PKI{
			Voting: &config.Voting{
				Authorities: []*authconfig.Authority{
					&authconfig.Authority{
						Identifier:         "dirauth1",
						IdentityPublicKey:  idpubkey,
						PKISignatureScheme: pkiScheme.Name(),
						LinkPublicKey:      linkpubkey,
						WireKEMScheme:      linkScheme.Name(),
						Addresses:          []string{"tcp://127.0.0.1:1234"},
					},
				},
			},
		},
		Identifier: "replica1",
		Logging: &config.Logging{
			Disable: false,
			File:    "",
			Level:   "DEBUG",
		},
		DataDir:            dname,
		SphinxGeometry:     geo,
		PKISignatureScheme: pkiScheme.Name(),
		ReplicaNIKEScheme:  replicaScheme.Name(),
		WireKEMScheme:      linkScheme.Name(),
		Addresses:          []string{"tcp://127.0.0.1:34394"},
	}

	pkiWorker := &PKIWorker{
		replicas:   common.NewReplicaMap(),
		WorkerBase: pki.NewWorkerBase(nil, nil), // No PKI client needed for test
	}

	s := &Server{
		identityPublicKey: pk,
		cfg:               cfg,
		logBackend:        logBackend,
		PKIWorker:         pkiWorker,
	}
	pkiWorker.server = s
	s.connector = newMockConnector(s)

	epoch, _, _ := epochtime.Now()

	// Create a PKI document with the test replica
	doc := &pki.Document{
		Epoch: epoch,
		StorageReplicas: []*pki.ReplicaDescriptor{
			dstReplicaDesc,
		},
	}

	// Store the document in the PKI worker
	rawDoc, err := doc.MarshalCertificate()
	require.NoError(t, err)
	pkiWorker.StoreDocument(epoch, doc, rawDoc)

	adID := hash.Sum256(dstReplicaDesc.IdentityKey)
	pkiWorker.replicas.Replace(map[[32]byte]*pki.ReplicaDescriptor{adID: dstReplicaDesc})

	pkiWorker.server = s

	err = s.initLogging()
	require.NoError(t, err)

	outConn := newOutgoingConn(s.connector, dstReplicaDesc, geo, linkScheme)
	creds := &wire.PeerCredentials{}
	ok := outConn.IsPeerValid(creds)
	require.False(t, ok)

	creds = &wire.PeerCredentials{
		AdditionalData: adID[:],
		PublicKey:      linkpubkey,
	}
	ok = outConn.IsPeerValid(creds)
	require.True(t, ok)
}
