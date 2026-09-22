// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/katzenpost/katzenpost/client/thin"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		name      string
		sent      bool
		payloadOK bool
		err       error
		want      category
	}{
		{"delivered", true, true, nil, catDelivered},
		{"payload mismatch is lost", true, false, nil, catLost},
		{"overdue after send", true, false, thin.ErrReplyOverdue, catOverdue},
		{"connection lost is refused", false, false, thin.ErrConnectionLost, catRefused},
		{"connection lost wins over sent", true, false, thin.ErrConnectionLost, catRefused},
		{"daemon send failure is not-sent", false, false, fmt.Errorf("%w: no route", thin.ErrSendFailed), catNotSent},
		{"send failure wins over sent", true, false, thin.ErrSendFailed, catNotSent},
		{"sent then deadline is lost", true, false, context.DeadlineExceeded, catLost},
		{"queued then deadline is not-sent", false, false, context.DeadlineExceeded, catNotSent},
		{"unsent opaque error is not-sent", false, false, errors.New("dial: broken pipe"), catNotSent},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classify(tc.sent, tc.payloadOK, tc.err)
			if got != tc.want {
				t.Fatalf("classify(sent=%v, ok=%v, err=%v) = %v, want %v",
					tc.sent, tc.payloadOK, tc.err, got, tc.want)
			}
		})
	}
}

// TestFailingCountsOverdueAsLoss pins that the default gate treats an overdue
// reply as loss. Every dispatched packet that never comes back lands in
// catOverdue, not catLost, because the overdue timer always fires first.
func TestFailingCountsOverdueAsLoss(t *testing.T) {
	var c counts
	c[catDelivered] = 7
	c[catOverdue] = 2
	c[catNotSent] = 1

	if got := c.failing(false); got != 2 {
		t.Fatalf("failing(false) = %d, want 2", got)
	}
	if got := c.failing(true); got != 3 {
		t.Fatalf("failing(true) = %d, want 3", got)
	}
}

// TestFailingIgnoresClientSideLimits pins the other half: a run held back by
// the client's own pacing is not a mixnet failure.
func TestFailingIgnoresClientSideLimits(t *testing.T) {
	var c counts
	c[catDelivered] = 5
	c[catNotSent] = 3
	c[catRefused] = 2

	if got := c.failing(false); got != 0 {
		t.Fatalf("failing(false) = %d, want 0", got)
	}
	if got := c.failing(true); got != 5 {
		t.Fatalf("failing(true) = %d, want 5", got)
	}
}
