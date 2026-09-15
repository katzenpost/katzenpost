// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"crypto/rand"
	"runtime"
	"sync"
	"time"

	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/hpqc/kem"
	kemschemes "github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/nike"
	nikeschemes "github.com/katzenpost/hpqc/nike/schemes"

	"github.com/katzenpost/katzenpost/core/sphinx"
	"github.com/katzenpost/katzenpost/core/sphinx/commands"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/server/internal/instrument"
)

// The mix-server startup self-check times Sphinx Unwrap operations
// against a freshly built test packet and publishes the result to
// prometheus. Two modes are measured:
//
//  1. "solo": a single goroutine running Unwrap back-to-back. This is
//     the best-case per-core throughput and represents what a server
//     achieves on a host where no other CPU-heavy work is happening.
//
//  2. "saturated": runtime.NumCPU goroutines all running Unwrap
//     concurrently. The server process is fully loaded on every core,
//     which mimics what happens when its own cryptoworkers all hit
//     Sphinx unwrap at once, OR when sibling katzenpost processes on
//     the same host are also crunching. The aggregate ops/sec from
//     this mode is the realistic ceiling for a CPU-saturated server
//     process on a contended host.
//
// Same shape and same set of three prometheus gauges as the replica
// CTIDH self-check in replica/selfcheck.go.
const (
	sphinxSelfCheckIterations          = 5
	sphinxSelfCheckWarmup              = 1
	sphinxSelfCheckSaturatedIterations = 5
)

// SphinxSelfCheckResult is the structured output of the self check.
type SphinxSelfCheckResult struct {
	// OpsPerSecPerCore is the per-core rate measured with a single
	// goroutine: the best-case-per-core throughput.
	OpsPerSecPerCore float64

	// OpsPerSecSaturated is the aggregate rate measured with NumCPU
	// goroutines running Unwrap in parallel: the realistic ceiling
	// for one server process when its own request handlers or other
	// co-tenanted processes are fully utilising the host.
	OpsPerSecSaturated float64

	// NumCPU is runtime.NumCPU at startup time.
	NumCPU int

	// IterationTime is the average single-op cost in solo mode.
	IterationTime time.Duration
}

// runSphinxSelfCheck performs both the solo and saturated measurements
// (in that order) and publishes the results to prometheus.
func runSphinxSelfCheck(log *logging.Logger, geometry *geo.Geometry) SphinxSelfCheckResult {
	numCPU := runtime.NumCPU()

	if geometry == nil {
		log.Warning("self-check: SphinxGeometry is nil; skipping Sphinx self-check")
		return SphinxSelfCheckResult{NumCPU: numCPU}
	}

	sph, err := sphinx.FromGeometry(geometry)
	if err != nil {
		log.Warningf("self-check: FromGeometry failed (%v); skipping Sphinx self-check", err)
		return SphinxSelfCheckResult{NumCPU: numCPU}
	}

	pkt, privateKey, err := buildSphinxSelfCheckPacket(geometry)
	if err != nil {
		log.Warningf("self-check: buildSphinxSelfCheckPacket failed (%v); skipping Sphinx self-check", err)
		return SphinxSelfCheckResult{NumCPU: numCPU}
	}

	// Solo mode. Each Unwrap consumes the packet bytes in place
	// (modifies them), so refresh from the prepared copy on every
	// iteration.
	for i := 0; i < sphinxSelfCheckWarmup; i++ {
		test := make([]byte, len(pkt))
		copy(test, pkt)
		_, _, _, _ = sph.Unwrap(privateKey, test)
	}
	start := time.Now()
	for i := 0; i < sphinxSelfCheckIterations; i++ {
		test := make([]byte, len(pkt))
		copy(test, pkt)
		if _, _, _, err := sph.Unwrap(privateKey, test); err != nil {
			log.Warningf("self-check: solo Unwrap failed at iter %d (%v); skipping", i, err)
			return SphinxSelfCheckResult{NumCPU: numCPU}
		}
	}
	elapsedSolo := time.Since(start)
	perOp := elapsedSolo / time.Duration(sphinxSelfCheckIterations)
	opsPerSecSolo := float64(sphinxSelfCheckIterations) / elapsedSolo.Seconds()

	// Saturated mode: numCPU goroutines each do
	// sphinxSelfCheckSaturatedIterations Unwrap ops concurrently.
	saturatedTotalOps := numCPU * sphinxSelfCheckSaturatedIterations
	var wg sync.WaitGroup
	startSat := time.Now()
	for w := 0; w < numCPU; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < sphinxSelfCheckSaturatedIterations; i++ {
				test := make([]byte, len(pkt))
				copy(test, pkt)
				_, _, _, _ = sph.Unwrap(privateKey, test)
			}
		}()
	}
	wg.Wait()
	elapsedSat := time.Since(startSat)
	opsPerSecSaturated := float64(saturatedTotalOps) / elapsedSat.Seconds()

	idealAggregate := opsPerSecSolo * float64(numCPU)
	var scaling float64
	if idealAggregate > 0 {
		scaling = opsPerSecSaturated / idealAggregate
	}

	log.Noticef(
		"Sphinx self-check: solo=%.2f Unwrap ops/s/core (one op ≈ %s); "+
			"saturated (NumCPU=%d goroutines in parallel)=%.2f aggregate ops/s; "+
			"scaling efficiency=%.0f%% of solo×NumCPU. "+
			"Use the saturated number as the realistic per-process ceiling on this host; "+
			"divide by the count of co-tenanted katzenpost processes for the per-process share.",
		opsPerSecSolo, perOp.Round(time.Millisecond),
		numCPU, opsPerSecSaturated,
		scaling*100,
	)

	instrument.SelfCheckResults(opsPerSecSolo, opsPerSecSaturated, numCPU)

	return SphinxSelfCheckResult{
		OpsPerSecPerCore:   opsPerSecSolo,
		OpsPerSecSaturated: opsPerSecSaturated,
		NumCPU:             numCPU,
		IterationTime:      perOp,
	}
}

// buildSphinxSelfCheckPacket prepares a representative Sphinx packet
// that can be unwrapped repeatedly to benchmark the hot path. Returns
// the packet bytes and the first hop's private key.
func buildSphinxSelfCheckPacket(geometry *geo.Geometry) ([]byte, interface{}, error) {
	if geometry.NIKEName != "" {
		scheme := nikeschemes.ByName(geometry.NIKEName)
		if scheme == nil {
			return nil, nil, errSelfCheckScheme
		}
		return buildNIKESelfCheckPacket(geometry, scheme)
	}
	scheme := kemschemes.ByName(geometry.KEMName)
	if scheme == nil {
		return nil, nil, errSelfCheckScheme
	}
	return buildKEMSelfCheckPacket(geometry, scheme)
}

func buildNIKESelfCheckPacket(geometry *geo.Geometry, scheme nike.Scheme) ([]byte, interface{}, error) {
	sph, err := sphinx.FromGeometry(geometry)
	if err != nil {
		return nil, nil, err
	}
	pubkeys := make([]nike.PublicKey, geometry.NrHops)
	privkeys := make([]nike.PrivateKey, geometry.NrHops)
	for i := 0; i < geometry.NrHops; i++ {
		pub, priv, err := scheme.GenerateKeyPair()
		if err != nil {
			return nil, nil, err
		}
		pubkeys[i] = pub
		privkeys[i] = priv
	}
	path := buildNIKEPath(geometry.NrHops, pubkeys)
	payload := make([]byte, geometry.ForwardPayloadLength)
	pkt, err := sph.NewPacket(rand.Reader, path, payload)
	if err != nil {
		return nil, nil, err
	}
	return pkt, privkeys[0], nil
}

func buildKEMSelfCheckPacket(geometry *geo.Geometry, scheme kem.Scheme) ([]byte, interface{}, error) {
	sph, err := sphinx.FromGeometry(geometry)
	if err != nil {
		return nil, nil, err
	}
	pubkeys := make([]kem.PublicKey, geometry.NrHops)
	privkeys := make([]kem.PrivateKey, geometry.NrHops)
	for i := 0; i < geometry.NrHops; i++ {
		pub, priv, err := scheme.GenerateKeyPair()
		if err != nil {
			return nil, nil, err
		}
		pubkeys[i] = pub
		privkeys[i] = priv
	}
	path := buildKEMPath(geometry.NrHops, pubkeys)
	payload := make([]byte, geometry.ForwardPayloadLength)
	pkt, err := sph.NewPacket(rand.Reader, path, payload)
	if err != nil {
		return nil, nil, err
	}
	return pkt, privkeys[0], nil
}

func buildNIKEPath(nrHops int, pubkeys []nike.PublicKey) []*sphinx.PathHop {
	path := make([]*sphinx.PathHop, nrHops)
	for i := 0; i < nrHops; i++ {
		path[i] = new(sphinx.PathHop)
		_, _ = rand.Read(path[i].ID[:])
		path[i].NIKEPublicKey = pubkeys[i]
		if i < nrHops-1 {
			delay := new(commands.NodeDelay)
			delay.Delay = 1
			path[i].Commands = append(path[i].Commands, delay)
		} else {
			recipient := new(commands.Recipient)
			_, _ = rand.Read(recipient.ID[:])
			path[i].Commands = append(path[i].Commands, recipient)
		}
	}
	return path
}

func buildKEMPath(nrHops int, pubkeys []kem.PublicKey) []*sphinx.PathHop {
	path := make([]*sphinx.PathHop, nrHops)
	for i := 0; i < nrHops; i++ {
		path[i] = new(sphinx.PathHop)
		_, _ = rand.Read(path[i].ID[:])
		path[i].KEMPublicKey = pubkeys[i]
		if i < nrHops-1 {
			delay := new(commands.NodeDelay)
			delay.Delay = 1
			path[i].Commands = append(path[i].Commands, delay)
		} else {
			recipient := new(commands.Recipient)
			_, _ = rand.Read(recipient.ID[:])
			path[i].Commands = append(path[i].Commands, recipient)
		}
	}
	return path
}

var errSelfCheckScheme = sphinxSelfCheckError("unable to resolve Sphinx scheme by name")

type sphinxSelfCheckError string

func (e sphinxSelfCheckError) Error() string { return string(e) }
