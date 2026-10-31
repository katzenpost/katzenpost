// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package pigeonservice

import (
	"context"
	"errors"
	"math/rand/v2"
	"time"

	"github.com/katzenpost/hpqc/bacap"
)

// DefaultPollInterval is how long a reader waits before asking again for a
// box that has not been written yet.
const DefaultPollInterval = 5 * time.Second

// retryInterval is how long a failed write or read waits before retrying.
const retryInterval = 2 * time.Second

func sleep(ctx context.Context, d time.Duration) error {
	// Jitter keeps many readers from asking in lockstep.
	d += time.Duration(rand.Int64N(int64(d)/4 + 1))
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// ReadWait reads a box, waiting until it is written. Each attempt is a
// fresh read: the daemon's own retry is tied to one replica epoch and would
// stall across an epoch change. A tombstone is returned as ErrTombstone
// along with the index after it. Other failures are retried until ctx ends.
func ReadWait(ctx context.Context, ph Pigeonhole, readCap *bacap.ReadCap, idx *bacap.MessageBoxIndex, interval time.Duration) ([]byte, *bacap.MessageBoxIndex, error) {
	if interval <= 0 {
		interval = DefaultPollInterval
	}
	for {
		plaintext, next, err := ph.Read(ctx, readCap, idx)
		switch {
		case err == nil, errors.Is(err, ErrTombstone):
			return plaintext, next, err
		case ctx.Err() != nil:
			return nil, nil, ctx.Err()
		case errors.Is(err, ErrBoxNotFound):
			err = sleep(ctx, interval)
		default:
			err = sleep(ctx, retryInterval)
		}
		if err != nil {
			return nil, nil, err
		}
	}
}

// WriteRetry writes a box, retrying failures until ctx ends. A repeated
// write of the same box is an idempotent success, so retrying is safe.
func WriteRetry(ctx context.Context, ph Pigeonhole, writeCap *bacap.WriteCap, idx *bacap.MessageBoxIndex, plaintext []byte) (*bacap.MessageBoxIndex, error) {
	for {
		next, err := ph.Write(ctx, writeCap, idx, plaintext)
		if err == nil {
			return next, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if err := sleep(ctx, retryInterval); err != nil {
			return nil, err
		}
	}
}
