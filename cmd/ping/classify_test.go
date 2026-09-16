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
