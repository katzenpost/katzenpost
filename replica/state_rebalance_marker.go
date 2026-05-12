// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"errors"
	"sort"

	"github.com/linxGnu/grocksdb"
	"golang.org/x/crypto/blake2b"

	"github.com/katzenpost/katzenpost/core/pki"
)

// lastRebalanceReplicasKey names the metadata-CF entry that records the
// storage-replica-set fingerprint at the time of our last successful
// Rebalance. Its sole reader is the startup gate in server.go, which
// consults it to decide whether a fresh boot-time rebalance is needed.
var lastRebalanceReplicasKey = []byte("last_rebalance_replicas")

// replicaSetFingerprint returns a canonical 32-byte digest of the
// storage-replica membership advertised by the supplied PKI document.
// The digest is the BLAKE2b-256 of the lexicographically sorted
// concatenation of each replica's identity-key BLAKE2b-256 hash, which
// is the same hash already used elsewhere in this package to address
// replicas. Sorting yields ordering-independence, so two PKI documents
// that list the same replicas in different orders produce identical
// fingerprints.
func replicaSetFingerprint(doc *pki.Document) [32]byte {
	if doc == nil || len(doc.StorageReplicas) == 0 {
		return blake2b.Sum256(nil)
	}
	hashes := make([][32]byte, 0, len(doc.StorageReplicas))
	for _, replica := range doc.StorageReplicas {
		hashes = append(hashes, blake2b.Sum256(replica.IdentityKey))
	}
	sort.Slice(hashes, func(i, j int) bool {
		for k := 0; k < 32; k++ {
			if hashes[i][k] != hashes[j][k] {
				return hashes[i][k] < hashes[j][k]
			}
		}
		return false
	})
	concatenated := make([]byte, 0, 32*len(hashes))
	for _, h := range hashes {
		concatenated = append(concatenated, h[:]...)
	}
	return blake2b.Sum256(concatenated)
}

// loadLastRebalanceFingerprint returns the persisted fingerprint, an
// "exists" flag, and any read error. A missing record yields
// (zero, false, nil); the caller treats that as "no prior rebalance
// recorded" and proceeds.
func (s *state) loadLastRebalanceFingerprint() ([32]byte, bool, error) {
	var zero [32]byte
	if s.db == nil || s.metaCF == nil {
		return zero, false, errors.New(errDatabaseClosed)
	}
	ro := grocksdb.NewDefaultReadOptions()
	defer ro.Destroy()
	value, err := s.db.GetCF(ro, s.metaCF, lastRebalanceReplicasKey)
	if err != nil {
		return zero, false, err
	}
	defer value.Free()
	if value.Size() == 0 {
		return zero, false, nil
	}
	if value.Size() != 32 {
		s.log.Warningf("state: discarding malformed rebalance-fingerprint record of size %d", value.Size())
		return zero, false, nil
	}
	var fp [32]byte
	copy(fp[:], value.Data())
	return fp, true, nil
}

// storeLastRebalanceFingerprint overwrites the persisted fingerprint
// with the supplied value. Called only after a Rebalance iterator
// completes without error.
func (s *state) storeLastRebalanceFingerprint(fp [32]byte) error {
	if s.db == nil || s.metaCF == nil {
		return errors.New(errDatabaseClosed)
	}
	wo := grocksdb.NewDefaultWriteOptions()
	defer wo.Destroy()
	return s.db.PutCF(wo, s.metaCF, lastRebalanceReplicasKey, fp[:])
}
