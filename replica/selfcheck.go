// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"runtime"
	"sync"
	"time"

	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/rand"

	replicaCommon "github.com/katzenpost/katzenpost/replica/common"
	"github.com/katzenpost/katzenpost/replica/instrument"
)

// The replica startup self-check times MKEM (CTIDH1024-X25519)
// Decapsulate operations against a freshly generated keypair and
// publishes the result to prometheus. Two modes are measured:
//
//  1. "solo": a single goroutine running Decapsulate back-to-back. This
//     is the best-case per-core throughput and represents what a
//     replica achieves on a host where no other CPU-heavy work is
//     happening. The "ops/sec/core" gauge derives from this.
//
//  2. "saturated": runtime.NumCPU goroutines all running Decapsulate
//     concurrently. The replica process is fully loaded on every core,
//     which mimics what happens when its own request handlers all hit
//     CTIDH at once, OR when sibling replicas on the same host are
//     also computing. The aggregate ops/sec from this mode is the
//     realistic ceiling for a CPU-saturated replica process on a
//     contended host.
//
// Why both: a single-replica-per-machine deployment will approach the
// solo per-core number times the number of cores it actually gets to
// use; a docker-mixnet or any co-tenanted deployment will be closer
// to the saturated aggregate divided by the number of replicas
// sharing the host. Ops teams should look at the saturated number to
// size queues and the solo number to size ProxyWorkerCount on a
// per-replica basis.
const (
	mkemSelfCheckIterations          = 5
	mkemSelfCheckWarmup              = 1
	mkemSelfCheckPayload             = 256
	mkemSelfCheckSaturatedIterations = 5
)

// MKEMSelfCheckResult is the structured output of the self check, kept
// alongside the publishing side-effects so unit tests and callers
// without a prometheus listener can still inspect the measurement.
type MKEMSelfCheckResult struct {
	// OpsPerSecPerCore is the per-core rate measured with a single
	// goroutine: the best-case-per-core throughput.
	OpsPerSecPerCore float64

	// OpsPerSecSaturated is the aggregate rate measured with NumCPU
	// goroutines running Decapsulate in parallel: the realistic
	// ceiling for one replica process when its own request handlers
	// or other co-tenanted processes are fully utilising the host.
	OpsPerSecSaturated float64

	// NumCPU is runtime.NumCPU at startup time.
	NumCPU int

	// IterationTime is the average single-op cost in solo mode.
	IterationTime time.Duration
}

// runMKEMSelfCheck performs both the solo and saturated measurements
// (in that order) and publishes the results to prometheus. It returns
// a structured result for callers that need to consume the numbers
// directly, e.g. for ProxyWorkerCount recommendations.
func runMKEMSelfCheck(log *logging.Logger) MKEMSelfCheckResult {
	scheme := replicaCommon.MKEMNikeScheme
	nikeScheme := replicaCommon.NikeScheme
	numCPU := runtime.NumCPU()

	pubKey, privKey, err := nikeScheme.GenerateKeyPair()
	if err != nil {
		log.Warningf("self-check: GenerateKeyPair failed (%v); skipping CTIDH self-check", err)
		return MKEMSelfCheckResult{NumCPU: numCPU}
	}

	payload := make([]byte, mkemSelfCheckPayload)
	if _, err := rand.Reader.Read(payload); err != nil {
		log.Warningf("self-check: rand.Read failed (%v); skipping CTIDH self-check", err)
		return MKEMSelfCheckResult{NumCPU: numCPU}
	}

	// Build a representative ciphertext once. Decapsulate is the hot
	// path; Encapsulate happens at lower frequency on the reply side
	// so we don't bench it.
	_, ct := scheme.Encapsulate([]nike.PublicKey{pubKey}, payload)

	// Solo mode: warm up, then time mkemSelfCheckIterations ops in one
	// goroutine.
	for i := 0; i < mkemSelfCheckWarmup; i++ {
		_, _ = scheme.Decapsulate(privKey, ct)
	}
	start := time.Now()
	for i := 0; i < mkemSelfCheckIterations; i++ {
		if _, err := scheme.Decapsulate(privKey, ct); err != nil {
			log.Warningf("self-check: solo Decapsulate failed at iter %d (%v); skipping", i, err)
			return MKEMSelfCheckResult{NumCPU: numCPU}
		}
	}
	elapsedSolo := time.Since(start)
	perOp := elapsedSolo / time.Duration(mkemSelfCheckIterations)
	opsPerSecSolo := float64(mkemSelfCheckIterations) / elapsedSolo.Seconds()

	// Saturated mode: numCPU goroutines each do
	// mkemSelfCheckSaturatedIterations Decapsulate ops concurrently.
	// Total ops = numCPU * iterations. Wall clock to finish all of
	// them is the saturated cost; aggregate ops/sec = total / elapsed.
	saturatedTotalOps := numCPU * mkemSelfCheckSaturatedIterations
	var wg sync.WaitGroup
	startSat := time.Now()
	for w := 0; w < numCPU; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < mkemSelfCheckSaturatedIterations; i++ {
				if _, err := scheme.Decapsulate(privKey, ct); err != nil {
					return
				}
			}
		}()
	}
	wg.Wait()
	elapsedSat := time.Since(startSat)
	opsPerSecSaturated := float64(saturatedTotalOps) / elapsedSat.Seconds()

	// Scaling factor: a perfectly parallel CPU would achieve numCPU *
	// opsPerSecSolo at saturation. The ratio between the measured
	// saturated rate and this ideal tells ops teams how
	// well their cores actually scale for CTIDH, which depends on the
	// host's thermal headroom, SMT/hyperthreading, and any cgroup or
	// container CPU limits in effect.
	idealAggregate := opsPerSecSolo * float64(numCPU)
	var scaling float64
	if idealAggregate > 0 {
		scaling = opsPerSecSaturated / idealAggregate
	}

	log.Noticef(
		"CTIDH self-check: solo=%.2f ops/s/core (one op ≈ %s); "+
			"saturated (NumCPU=%d goroutines in parallel)=%.2f aggregate ops/s; "+
			"scaling efficiency=%.0f%% of solo×NumCPU. "+
			"Use the saturated number as the realistic per-replica ceiling on this host; "+
			"divide by the count of co-tenanted replicas for the per-replica share.",
		opsPerSecSolo, perOp.Round(time.Millisecond),
		numCPU, opsPerSecSaturated,
		scaling*100,
	)

	instrument.SelfCheckResults(opsPerSecSolo, opsPerSecSaturated, numCPU)

	return MKEMSelfCheckResult{
		OpsPerSecPerCore:   opsPerSecSolo,
		OpsPerSecSaturated: opsPerSecSaturated,
		NumCPU:             numCPU,
		IterationTime:      perOp,
	}
}
