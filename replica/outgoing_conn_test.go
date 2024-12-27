// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"fmt"
	"os"
	"sync"
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
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/replica/config"
)

func TestOutgoingConn(t *testing.T) {
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
	idpubkeyblob, err := idpubkey.MarshalBinary()
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

	s := &Server{
		identityPublicKey: pk,
		cfg:               cfg,
		pkiWorker: &PKIWorker{
			replicas:      newReplicaMap(),
			lock:          new(sync.RWMutex),
			docs:          make(map[uint64]*pki.Document),
			rawDocs:       make(map[uint64][]byte),
			failedFetches: make(map[uint64]error),
		},
	}
	s.pkiWorker.server = s
	s.connector = newMockConnector(s)

	epoch, _, _ := epochtime.Now()
	s.pkiWorker.lock.Lock()
	s.pkiWorker.docs[epoch] = &pki.Document{
		Epoch: epoch,
		ServiceNodes: []*pki.MixDescriptor{
			&pki.MixDescriptor{
				Name:        "servicenode1",
				Epoch:       epoch,
				IdentityKey: idpubkeyblob,
				LinkKey:     dstReplicaDesc.LinkKey,
			},
		},
	}
	s.pkiWorker.docs[epoch] = &pki.Document{
		Epoch: epoch,
		StorageReplicas: []*pki.ReplicaDescriptor{
			dstReplicaDesc,
		},
	}
	adID := hash.Sum256(dstReplicaDesc.IdentityKey)
	s.pkiWorker.replicas.Replace(map[[32]byte]*pki.ReplicaDescriptor{adID: dstReplicaDesc})

	s.pkiWorker.lock.Unlock()
	s.pkiWorker.server = s
	s.pkiWorker.log = s.LogBackend().GetLogger("pki")

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
