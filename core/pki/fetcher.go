// SPDX-FileCopyrightText: © 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package pki

import (
	"context"

	"gopkg.in/op/go-logging.v1"
)

// DocumentFetcher provides common PKI document fetching functionality
type DocumentFetcher struct {
	log    *logging.Logger
	client Client
}

// NewDocumentFetcher creates a new document fetcher
func NewDocumentFetcher(client Client, log *logging.Logger) *DocumentFetcher {
	return &DocumentFetcher{
		log:    log,
		client: client,
	}
}

// FetchDocumentResult represents the result of fetching a single document
type FetchDocumentResult struct {
	Epoch   uint64
	Doc     *Document
	RawDoc  []byte
	Error   error
	Skipped bool
}

// FetchDocuments fetches PKI documents for the given epochs
func (f *DocumentFetcher) FetchDocuments(
	ctx context.Context,
	epochs []uint64,
	isCanceled func() bool,
	getFailedFetch func(uint64) (bool, error),
	setFailedFetch func(uint64, error),
) []FetchDocumentResult {
	results := make([]FetchDocumentResult, 0, len(epochs))

	for _, epoch := range epochs {
		f.log.Debugf("PKI worker, fetching document for epoch %d", epoch)

		// Check for previous failures
		if ok, err := getFailedFetch(epoch); ok {
			f.log.Debugf("Skipping fetch for epoch %v: %v", epoch, err)
			results = append(results, FetchDocumentResult{
				Epoch:   epoch,
				Skipped: true,
				Error:   err,
			})
			continue
		}

		// Fetch the document
		d, rawDoc, err := f.client.GetPKIDocumentForEpoch(ctx, epoch)
		if isCanceled() {
			f.log.Debug("Canceled mid-fetch")
			return results
		}

		result := FetchDocumentResult{
			Epoch:  epoch,
			Doc:    d,
			RawDoc: rawDoc,
			Error:  err,
		}

		if err != nil {
			f.log.Warningf("Failed to fetch PKI for epoch %v: %v", epoch, err)
			if err == ErrDocumentGone {
				setFailedFetch(epoch, err)
			}
		}

		results = append(results, result)
	}

	return results
}
