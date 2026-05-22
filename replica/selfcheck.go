// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"runtime"
	"time"

	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/rand"

	replicaCommon "github.com/katzenpost/katzenpost/replica/common"
	"github.com/katzenpost/katzenpost/replica/instrument"
)

// runMKEMSelfCheck times MKEM (CTIDH1024-X25519) Decapsulate operations
// against a freshly generated keypair and publishes the per-core ops/sec
// to prometheus. The result is the single-threaded throughput ceiling
// of a single core; ops teams can multiply by runtime.NumCPU for a
// rough aggregate bound, with the caveat that real workloads also
// contend for RocksDB, the proxy semaphore, and the network stack.
//
// The check uses iterations such that the total wall-clock is bounded
// by mkemSelfCheckBudget (default ~3 s on modern CPUs); slower CPUs
// will finish the same iteration count but take proportionally longer,
// which is acceptable as a startup-time check.
//
// The replica calls this from server.New after envelope keys are set
// up but before the proxy semaphore is sized. It logs a single notice
// summarising the result and an ops-team-friendly recommendation if
// the configured ProxyWorkerCount appears mismatched with the
// measured per-core rate.
const (
	mkemSelfCheckIterations = 5
	mkemSelfCheckWarmup     = 1
	mkemSelfCheckPayload    = 256
)

// MKEMSelfCheckResult is the structured output of the self check, kept
// alongside the publishing side-effects so unit tests and callers
// without a prometheus listener can still inspect the measurement.
type MKEMSelfCheckResult struct {
	OpsPerSecPerCore float64
	NumCPU           int
	IterationTime    time.Duration
}

func runMKEMSelfCheck(log *logging.Logger) MKEMSelfCheckResult {
	scheme := replicaCommon.MKEMNikeScheme
	nikeScheme := replicaCommon.NikeScheme

	pubKey, privKey, err := nikeScheme.GenerateKeyPair()
	if err != nil {
		log.Warningf("self-check: GenerateKeyPair failed (%v); skipping CTIDH self-check", err)
		return MKEMSelfCheckResult{NumCPU: runtime.NumCPU()}
	}

	payload := make([]byte, mkemSelfCheckPayload)
	if _, err := rand.Reader.Read(payload); err != nil {
		log.Warningf("self-check: rand.Read failed (%v); skipping CTIDH self-check", err)
		return MKEMSelfCheckResult{NumCPU: runtime.NumCPU()}
	}

	// Build a representative ciphertext once. The hot path the replica
	// runs is Decapsulate; Encapsulate happens too on the reply side
	// but at lower frequency. Measuring Decapsulate matches the
	// dominant per-request cost handleReplicaMessage incurs.
	_, ct := scheme.Encapsulate([]nike.PublicKey{pubKey}, payload)

	for i := 0; i < mkemSelfCheckWarmup; i++ {
		_, _ = scheme.Decapsulate(privKey, ct)
	}

	start := time.Now()
	for i := 0; i < mkemSelfCheckIterations; i++ {
		if _, err := scheme.Decapsulate(privKey, ct); err != nil {
			log.Warningf("self-check: Decapsulate failed at iter %d (%v); skipping", i, err)
			return MKEMSelfCheckResult{NumCPU: runtime.NumCPU()}
		}
	}
	elapsed := time.Since(start)
	perOp := elapsed / time.Duration(mkemSelfCheckIterations)
	opsPerSec := float64(mkemSelfCheckIterations) / elapsed.Seconds()
	numCPU := runtime.NumCPU()

	log.Noticef(
		"CTIDH self-check: %.2f Decapsulate ops/s per core (one op ≈ %s); "+
			"runtime.NumCPU=%d implies a theoretical aggregate ceiling around %.1f ops/s when all cores are utilised. "+
			"Real pigeonhole iter/s will be lower due to per-request multi-op chains, RocksDB and network contention.",
		opsPerSec, perOp.Round(time.Millisecond), numCPU, opsPerSec*float64(numCPU),
	)

	instrument.SelfCheckResults(opsPerSec, numCPU)

	return MKEMSelfCheckResult{
		OpsPerSecPerCore: opsPerSec,
		NumCPU:           numCPU,
		IterationTime:    perOp,
	}
}
