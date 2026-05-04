// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package pki

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func newTestWorkerBase() *WorkerBase {
	return &WorkerBase{
		lock:          new(sync.RWMutex),
		docs:          make(map[uint64]*Document),
		rawDocs:       make(map[uint64][]byte),
		failedFetches: make(map[uint64]error),
	}
}

func TestLastCachedPKIDocumentEmpty(t *testing.T) {
	w := newTestWorkerBase()
	require.Nil(t, w.LastCachedPKIDocument())
}

func TestLastCachedPKIDocumentReturnsNewest(t *testing.T) {
	w := newTestWorkerBase()
	d100 := &Document{Epoch: 100}
	d101 := &Document{Epoch: 101}
	d99 := &Document{Epoch: 99}

	// Insertion order shouldn't matter.
	w.docs[100] = d100
	w.docs[99] = d99
	w.docs[101] = d101

	require.Same(t, d101, w.LastCachedPKIDocument())
}

func TestLastCachedPKIDocumentSingleEntry(t *testing.T) {
	w := newTestWorkerBase()
	d := &Document{Epoch: 42}
	w.docs[42] = d
	require.Same(t, d, w.LastCachedPKIDocument())
}
