// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"errors"

	"github.com/katzenpost/katzenpost/client/thin"
)

type category int

const (
	catDelivered category = iota
	catNotSent
	catRefused
	catOverdue
	catLost
	numCategories
)

func (c category) label() string {
	switch c {
	case catDelivered:
		return "delivered"
	case catNotSent:
		return "not-sent"
	case catRefused:
		return "refused"
	case catOverdue:
		return "overdue"
	case catLost:
		return "lost"
	default:
		return "unknown"
	}
}

// classify buckets one ping from the signals the thin client exposes: whether
// the daemon reported dispatching the packet, whether the reply matched, and
// the error the send returned.
func classify(sent, payloadOK bool, err error) category {
	switch {
	case err == nil:
		if payloadOK {
			return catDelivered
		}
		return catLost
	case errors.Is(err, thin.ErrReplyOverdue):
		return catOverdue
	case errors.Is(err, thin.ErrSendFailed):
		return catNotSent
	case errors.Is(err, thin.ErrConnectionLost):
		return catRefused
	case sent:
		return catLost
	default:
		return catNotSent
	}
}

// counts tallies ping outcomes by category.
type counts [numCategories]uint64

// failing returns how many outcomes count as failures for the exit gate. By
// default only genuine mixnet loss does; strict fails anything not delivered.
func (c counts) failing(strict bool) uint64 {
	if strict {
		var total uint64
		for _, n := range c {
			total += n
		}
		return total - c[catDelivered]
	}
	return c[catLost]
}
