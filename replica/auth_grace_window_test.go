// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/blake2b"

	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/pki"
	replicaCommon "github.com/katzenpost/katzenpost/replica/common"
)

// A peer present only in the PREVIOUS epoch's cached document must still
// authenticate: late dirauth publication or staggered-upgrade churn must
// not sever the mesh.
func TestReplicaDescriptorsForAuthGraceWindow(t *testing.T) {
	t.Parallel()

	backendLog, err := log.New("", "ERROR", false)
	require.NoError(t, err)
	logger := backendLog.GetLogger("test")

	identityKey := []byte("peer identity key bytes")
	nodeID := blake2b.Sum256(identityKey)
	desc := &pki.ReplicaDescriptor{
		Name:        "storagereplica9",
		IdentityKey: identityKey,
	}

	epoch, _, _ := epochtime.Now()
	prevDoc := &pki.Document{
		Epoch:           epoch - 1,
		StorageReplicas: []*pki.ReplicaDescriptor{desc},
	}

	w := &PKIWorker{
		WorkerBase: pki.NewWorkerBase(nil, logger),
		replicas:   replicaCommon.NewReplicaMap(),
	}
	w.SetDocumentForEpoch(epoch-1, prevDoc, nil)

	descs := w.replicaDescriptorsForAuth(&nodeID)
	require.Len(t, descs, 1)
	require.Equal(t, "storagereplica9", descs[0].Name)

	missing := blake2b.Sum256([]byte("nobody"))
	require.Empty(t, w.replicaDescriptorsForAuth(&missing))
}
