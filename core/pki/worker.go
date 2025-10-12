// SPDX-FileCopyrightText: © 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package pki

import (
	"context"
	"sync"
	"time"

	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/katzenpost/core/epochtime"
)

const NumPKIDocsToFetch = 3

var (
	// PublishConsensusDeadline is when the authority publishes the consensus
	PublishConsensusDeadline = epochtime.Period - (epochtime.Period / 8)
	mixServerCacheDelay      = epochtime.Period / 16
	nextFetchTill            = epochtime.Period - (PublishConsensusDeadline + mixServerCacheDelay)
	recheckInterval          = epochtime.Period / 32
)

// WorkerBase provides common PKI worker functionality shared between courier and replica
type WorkerBase struct {
	log     *logging.Logger
	impl    Client
	fetcher *DocumentFetcher

	lock          *sync.RWMutex
	docs          map[uint64]*Document
	rawDocs       map[uint64][]byte
	failedFetches map[uint64]error
}

// NewWorkerBase creates a new PKI worker base
func NewWorkerBase(impl Client, log *logging.Logger) *WorkerBase {
	return &WorkerBase{
		log:           log,
		impl:          impl,
		fetcher:       NewDocumentFetcher(impl, log),
		lock:          new(sync.RWMutex),
		docs:          make(map[uint64]*Document),
		rawDocs:       make(map[uint64][]byte),
		failedFetches: make(map[uint64]error),
	}
}

// DocumentsToFetch returns the list of epochs for which documents should be fetched
func (w *WorkerBase) DocumentsToFetch() []uint64 {
	ret := make([]uint64, 0, NumPKIDocsToFetch+1)
	now, _, till := epochtime.Now()
	start := now
	if till < nextFetchTill {
		start = now + 1
	}

	w.lock.RLock()
	defer w.lock.RUnlock()

	for epoch := start; epoch > now-NumPKIDocsToFetch; epoch-- {
		if _, ok := w.docs[epoch]; !ok {
			ret = append(ret, epoch)
		}
	}

	return ret
}

// GetFailedFetch checks if a fetch for the given epoch has previously failed
func (w *WorkerBase) GetFailedFetch(epoch uint64) (bool, error) {
	w.lock.RLock()
	defer w.lock.RUnlock()
	err, ok := w.failedFetches[epoch]
	return ok, err
}

// SetFailedFetch records a failed fetch for the given epoch
func (w *WorkerBase) SetFailedFetch(epoch uint64, err error) {
	w.lock.Lock()
	defer w.lock.Unlock()
	w.failedFetches[epoch] = err
}

// ClearFailedFetch removes a failed fetch record for the given epoch
func (w *WorkerBase) ClearFailedFetch(epoch uint64) {
	w.lock.Lock()
	defer w.lock.Unlock()
	delete(w.failedFetches, epoch)
}

// PruneFailures removes old failed fetch records
func (w *WorkerBase) PruneFailures() {
	w.lock.Lock()
	defer w.lock.Unlock()

	now, _, _ := epochtime.Now()

	for epoch := range w.failedFetches {
		// Be more aggressive about pruning failures than pruning documents,
		// the worst that can happen is that we query the PKI unneccecarily.
		if epoch < now-(NumPKIDocsToFetch-1) || epoch > now+1 {
			delete(w.failedFetches, epoch)
		}
	}
}

// PruneDocuments removes old PKI documents
func (w *WorkerBase) PruneDocuments() {
	now, _, _ := epochtime.Now()

	w.lock.Lock()
	defer w.lock.Unlock()
	for epoch := range w.docs {
		if epoch < now-(NumPKIDocsToFetch-1) {
			w.log.Debugf("Discarding PKI for epoch: %v", epoch)
			delete(w.docs, epoch)
			delete(w.rawDocs, epoch)
		}
		if epoch > now+1 {
			// This should NEVER happen.
			w.log.Debugf("Far future PKI document exists, clock ran backwards?: %v", epoch)
		}
	}
}

// PKIDocument returns the PKI document for the current epoch
func (w *WorkerBase) PKIDocument() *Document {
	epoch, _, _ := epochtime.Now()
	return w.EntryForEpoch(epoch)
}

// EntryForEpoch returns the PKI document for the specified epoch
func (w *WorkerBase) EntryForEpoch(epoch uint64) *Document {
	w.lock.RLock()
	defer w.lock.RUnlock()

	if d, ok := w.docs[epoch]; ok {
		return d
	}
	return nil
}

// UpdateTimer updates the timer for the next PKI worker wake-up
func (w *WorkerBase) UpdateTimer(timer *time.Timer) {
	now, elapsed, till := epochtime.Now()
	w.log.Debugf("pki woke %v into epoch %v with %v remaining", elapsed, now, till)

	// it's after the consensus publication deadline
	if elapsed > PublishConsensusDeadline {
		w.log.Debugf("After deadline for next epoch publication")
		if w.EntryForEpoch(now+1) == nil {
			w.log.Debugf("no document for %v yet, reset to %v", now+1, recheckInterval)
			timer.Reset(recheckInterval)
		} else {
			interval := till
			w.log.Debugf("document cached for %v, reset to %v", now+1, interval)
			timer.Reset(interval)
		}
	} else {
		w.log.Debugf("Not yet time for next epoch publication")
		// no document for current epoch
		if w.EntryForEpoch(now) == nil {
			w.log.Debugf("no document cached for current epoch %v, reset to %v", now, recheckInterval)
			timer.Reset(recheckInterval)
		} else {
			interval := PublishConsensusDeadline - elapsed
			w.log.Debugf("Document cached for current epoch %v, reset to %v", now, recheckInterval)
			timer.Reset(interval)
		}
	}
}

// FetchDocuments fetches PKI documents for required epochs using the shared fetcher
func (w *WorkerBase) FetchDocuments(pkiCtx context.Context, isCanceled func() bool) []FetchDocumentResult {
	epochs := w.DocumentsToFetch()
	if len(epochs) == 0 {
		return nil
	}

	return w.fetcher.FetchDocuments(
		pkiCtx,
		epochs,
		isCanceled,
		w.GetFailedFetch,
		w.SetFailedFetch,
	)
}

// StoreDocument stores a fetched document
func (w *WorkerBase) StoreDocument(epoch uint64, doc *Document, rawDoc []byte) {
	w.lock.Lock()
	defer w.lock.Unlock()
	w.rawDocs[epoch] = rawDoc
	w.docs[epoch] = doc
}

// SetDocumentForEpoch sets a PKI document for a specific epoch; for testing only
func (w *WorkerBase) SetDocumentForEpoch(epoch uint64, doc *Document, rawDoc []byte) {
	w.lock.Lock()
	defer w.lock.Unlock()
	w.docs[epoch] = doc
	w.rawDocs[epoch] = rawDoc
}

// GetLogger returns the logger instance
func (w *WorkerBase) GetLogger() *logging.Logger {
	return w.log
}

// SetupWorkerContext creates a context with cancellation for PKI workers
func SetupWorkerContext(haltCh <-chan interface{}, log *logging.Logger) (context.Context, context.CancelFunc, func() bool) {
	pkiCtx, cancelFn := context.WithCancel(context.Background())
	go func() {
		select {
		case <-haltCh:
			cancelFn()
		case <-pkiCtx.Done():
			log.Debug("<-pkiCtx.Done()")
		}
	}()

	isCanceled := func() bool {
		select {
		case <-pkiCtx.Done():
			return true
		default:
			return false
		}
	}

	return pkiCtx, cancelFn, isCanceled
}

// HandleTimerEvent processes timer and cancellation events
func HandleTimerEvent(timer *time.Timer, pkiCtx context.Context, haltCh <-chan interface{}, log *logging.Logger) bool {
	var timerFired bool
	select {
	case <-haltCh:
		log.Debug("Terminating gracefully.")
		return false
	case <-pkiCtx.Done():
		log.Debug("pkiCtx.Done")
		return false
	case <-timer.C:
		timerFired = true
	}

	if !timerFired && !timer.Stop() {
		select {
		case <-haltCh:
			log.Debug("Terminating gracefully.")
			return false
		case <-timer.C:
		}
	}
	return true
}
