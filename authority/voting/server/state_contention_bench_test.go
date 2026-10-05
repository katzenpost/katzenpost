// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/sign"

	"github.com/katzenpost/katzenpost/core/pki"
)

func newBenchConsensusState(b *testing.B) (*state, uint64) {
	st, key, votingEpoch := newSingleAuthorityState(b)
	pk := hash.Sum256From(key.idPubKey)
	st.verifiers = map[[publicKeyHashSize]byte]sign.PublicKey{pk: key.idPubKey}
	doc := &pki.Document{
		Epoch:              votingEpoch,
		GenesisEpoch:       votingEpoch,
		PKISignatureScheme: testSignatureScheme.Name(),
	}
	if _, err := pki.SignDocument(key.idKey, key.idPubKey, doc); err != nil {
		b.Fatal(err)
	}
	st.documents = map[uint64]*pki.Document{votingEpoch: doc}
	st.serializedDocs = map[uint64][]byte{}
	if _, err := st.documentForEpoch(votingEpoch); err != nil {
		b.Fatal(err)
	}
	return st, votingEpoch
}

func BenchmarkDocumentForEpochCached(b *testing.B) {
	st, epoch := newBenchConsensusState(b)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := st.documentForEpoch(epoch); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkDocumentForEpochCachedWithWriter(b *testing.B) {
	st, epoch := newBenchConsensusState(b)
	var stop atomic.Bool
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for !stop.Load() {
			st.Lock()
			st.votingEpoch++
			st.Unlock()
		}
	}()
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := st.documentForEpoch(epoch); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.StopTimer()
	stop.Store(true)
	wg.Wait()
}

func BenchmarkGetVerifiersLocked(b *testing.B) {
	st, _ := newBenchConsensusState(b)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			st.RLock()
			_ = st.getVerifiers()
			st.RUnlock()
		}
	})
}

func BenchmarkPhaseInfo(b *testing.B) {
	st, _ := newBenchConsensusState(b)
	st.cachedPhase.Store(stateAcceptDescriptor)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = st.PhaseInfo()
		}
	})
}
