// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/rand"
	nikeschemes "github.com/katzenpost/hpqc/nike/schemes"
	ecdh "github.com/katzenpost/hpqc/nike/x25519"
	signschemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/wire/commands"
	replicaCommon "github.com/katzenpost/katzenpost/replica/common"
	"github.com/katzenpost/katzenpost/replica/config"
)

// setupImmutabilityTestState spins up a replica state backed by a real
// RocksDB instance in a temp directory, suitable for exercising
// handleReplicaWrite concurrency.
func setupImmutabilityTestState(t *testing.T) *state {
	t.Helper()

	dname, err := os.MkdirTemp("", "replica.immutability")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dname) })

	nike := ecdh.Scheme(rand.Reader)
	geo := geo.GeometryFromUserForwardPayloadLength(nike, 1234, true, 5)
	require.NotNil(t, geo)

	pkiScheme := signschemes.ByName("ed25519")
	replicaScheme := nikeschemes.ByName("x25519")

	pk, _, err := pkiScheme.GenerateKey()
	require.NoError(t, err)

	cfg := &config.Config{
		ReplicaNIKEScheme: "X25519",
		DataDir:           dname,
		SphinxGeometry:    geo,
		Logging: &config.Logging{
			Disable: true,
			Level:   "ERROR",
		},
	}
	cfg.SetDefaultTimeouts()

	pkiWorker := &PKIWorker{
		replicas:   replicaCommon.NewReplicaMap(),
		WorkerBase: pki.NewWorkerBase(nil, nil),
	}

	s := &Server{
		identityPublicKey: pk,
		cfg:               cfg,
		PKIWorker:         pkiWorker,
		proxySema:         make(chan struct{}, cfg.ProxyWorkerCount),
	}
	s.connector = new(mockConnector)
	require.NoError(t, s.initLogging())
	pkiWorker.server = s

	st := &state{
		server: s,
		log:    s.LogBackend().GetLogger("state-immutability"),
	}
	st.initDB()
	t.Cleanup(st.Close)

	// Silence the unused symbol.
	_ = commands.NewStorageReplicaCommands(geo, replicaScheme)

	return st
}

// TestHandleReplicaWriteImmutableUnderConcurrency races many goroutines
// attempting to write the same BoxID with distinct signatures. The
// immutability guarantee requires that exactly one write succeeds and
// all others return ErrBoxAlreadyExists; without an atomic check-and-put
// the Get→check→Put window lets multiple writers believe they succeeded.
func TestHandleReplicaWriteImmutableUnderConcurrency(t *testing.T) {
	st := setupImmutabilityTestState(t)

	var boxID [bacap.BoxIDSize]byte
	_, err := rand.Reader.Read(boxID[:])
	require.NoError(t, err)

	const goroutines = 64

	var successCount atomic.Int32
	var alreadyExistsCount atomic.Int32
	var otherErrCount atomic.Int32

	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start

			// Give each goroutine a distinguishable signature so the state
			// store can tell whose write "won" if multiple succeeded.
			var sig [bacap.SignatureSize]byte
			sig[0] = byte(idx)
			sig[1] = byte(idx >> 8)

			cmd := &commands.ReplicaWrite{
				BoxID:     &boxID,
				Signature: &sig,
				Payload:   []byte("concurrent-write-payload"),
			}
			err := st.handleReplicaWrite(cmd)
			switch {
			case err == nil:
				successCount.Add(1)
			case errors.Is(err, ErrBoxAlreadyExists):
				alreadyExistsCount.Add(1)
			default:
				otherErrCount.Add(1)
				t.Logf("unexpected error from handleReplicaWrite: %v", err)
			}
		}(i)
	}
	close(start)
	wg.Wait()

	require.Equal(t, int32(0), otherErrCount.Load(), "no unexpected errors allowed")
	require.Equal(t, int32(1), successCount.Load(),
		"exactly one concurrent write must succeed (immutability)")
	require.Equal(t, int32(goroutines-1), alreadyExistsCount.Load(),
		"every other concurrent write must be rejected with ErrBoxAlreadyExists")
}
