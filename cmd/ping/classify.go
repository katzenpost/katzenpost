// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"errors"
	"fmt"

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

// dispatched reports whether the packet entered the mixnet, and so whether the
// outcome is evidence about it. A refused ping is excluded too: the daemon's
// link died before the reply could be observed, so the outcome is unknown
// rather than bad, whether or not the packet went out.
func (c category) dispatched() bool {
	return c == catDelivered || c == catLost || c == catOverdue
}

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

type counts [numCategories]uint64

func (c counts) total() uint64 {
	var total uint64
	for _, n := range c {
		total += n
	}
	return total
}

// failing returns the outcome count that gates a non-zero exit.
//
// An overdue reply counts as loss. The overdue deadline is ReplyETA plus
// replySlop, which is the same budget the daemon gives a SURB ID before it
// drops the map entry: the same hop count and the same per-hop figure, so the
// two deadlines coincide. A reply arriving after it can no longer be matched
// to its request and is discarded, which makes overdue an unrecoverable loss
// rather than a wait cut short.
//
// It is also where in-transit loss actually lands. The overdue timer always
// fires at or before the hard cap, since ReplyETA is bounded by hops times
// SafetyCap and the cap is hops times SafetyCap plus the same slop. Gating on
// catLost alone would therefore gate on a category a healthy run and a dead
// one both leave empty.
func (c counts) failing(strict bool) uint64 {
	notDelivered := c.total() - c[catDelivered]
	if strict {
		return notDelivered
	}
	// Floor: a run that delivered nothing at all fails whatever the
	// categories say. Not-sent and refused are excused individually
	// because the rest of the batch still measured the network; a batch
	// where they are the whole story measured nothing.
	if c[catDelivered] == 0 {
		return notDelivered
	}
	return c[catLost] + c[catOverdue]
}

// gateError reports the run's exit condition: nil when it passes, otherwise an
// error naming what failed.
func (c counts) gateError(strict bool, count int) error {
	failed := c.failing(strict)
	switch {
	case failed == 0:
		return nil
	case strict:
		return fmt.Errorf("%d/%d pings did not deliver", failed, count)
	case c[catDelivered] == 0:
		return fmt.Errorf("%d/%d pings failed and none delivered", failed, count)
	default:
		return fmt.Errorf("%d/%d pings lost in the mixnet", failed, count)
	}
}
