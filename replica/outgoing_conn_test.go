// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"

	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/replica/common"
)

func TestOutgoingConn(t *testing.T) {
	logBackend, err := log.New("", "DEBUG", false)
	require.NoError(t, err)

	// Setup test environment
	schemes := NewTestSchemes()
	geometry := CreateTestGeometryCustom(schemes, 1234, 5)
	tempDir := CreateTestTempDir(t, "replica_test_state")
	keys := GenerateTestKeys(t, schemes)

	dstReplicaDesc := GenerateTestReplica(t, schemes, 0)
	linkpubkey, err := schemes.Link.UnmarshalBinaryPublicKey(dstReplicaDesc.LinkKey)
	require.NoError(t, err)

	cfg := CreateTestConfig(t, schemes, geometry, tempDir, "replica1", []string{"tcp://127.0.0.1:34394"})

	pkiWorker := &PKIWorker{
		replicas:   common.NewReplicaMap(),
		WorkerBase: pki.NewWorkerBase(nil, nil), // No PKI client needed for test
	}

	s := &Server{
		identityPublicKey: keys.IdentityPubKey,
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

	outConn := newOutgoingConn(s.connector, dstReplicaDesc, geometry, schemes.Link)
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
