// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"errors"
	"sync"
)

// errSACKCancelled is returned by the controller when a transfer is torn
// down before every box was acknowledged, whether by an explicit cancel or
// by daemon shutdown.
var errSACKCancelled = errors.New("SACK write cancelled")

// boxSender is the seam between the windowed SACK controller and the live
// mixnet. The controller speaks only in box indices; the daemon satisfies
// this interface by enqueuing a per-box ARQ send onto the Poisson-gated
// egress path (send) and by cancelling an in-flight box's ARQ (cancel). A
// unit test satisfies it with a fake that records calls and lets the test
// grant or withhold acknowledgements deterministically.
//
// send is called only from the controller's single driver goroutine, so it
// may block (e.g. on a full egress queue) without stalling acknowledgement
// processing; it returns an error only when the box can never be put on the
// wire, which fails the whole transfer. Completion arrives later via boxAcked
// or boxFailed, called from the reply goroutine.
type boxSender interface {
	send(index int) error
	cancel(index int)
}

// sackController drives a windowed, selectively-acknowledged write of a
// sequence of pre-encrypted boxes. At most `window` boxes are in flight at
// once; as each box is acknowledged a queued box is admitted, keeping the
// window full until the queue drains.
//
// Per-box retransmission-until-ack is owned by the ARQ machinery behind the
// boxSender, not by this controller, so retransmits are inherently
// selective: only the box whose timer fires is resent, never the whole
// window. The controller's sole concern is admission, completion accounting,
// and teardown.
//
// A single driver goroutine (run) performs every send; acknowledgements and
// cancellations arrive from other goroutines and merely wake the driver. All
// shared state is guarded by mu.
type sackController struct {
	sender boxSender
	total  int
	window int

	mu        sync.Mutex
	next      int          // next box index not yet admitted
	inflight  map[int]bool // admitted but not yet acknowledged
	completed int          // boxes acknowledged
	results   [][]byte     // per-box payloads (reads); nil entries for writes
	finished  bool
	err       error

	wakeCh chan struct{} // buffered(1); pulsed on any state change
}

// newSACKController prepares a controller for a transfer of `total` boxes
// with at most `window` in flight. A window of zero or less, or larger than
// total, is clamped to total so the loop terminates sensibly.
func newSACKController(sender boxSender, total, window int) *sackController {
	if window <= 0 || window > total {
		window = total
	}
	return &sackController{
		sender:   sender,
		total:    total,
		window:   window,
		inflight: make(map[int]bool),
		results:  make([][]byte, total),
		wakeCh:   make(chan struct{}, 1),
	}
}

// run is the single driver goroutine. It keeps the window full and blocks
// until every box is acknowledged or the transfer is torn down, returning
// nil on full success or the failure/cancellation error otherwise. haltCh
// aborts the transfer on daemon shutdown.
func (c *sackController) run(haltCh <-chan interface{}) error {
	if c.total == 0 {
		return nil
	}
	for {
		if err := c.admit(); err != nil {
			c.cancel(err)
			return c.err
		}

		c.mu.Lock()
		switch {
		case c.finished:
			err := c.err
			c.mu.Unlock()
			return err
		case c.completed == c.total:
			c.mu.Unlock()
			c.finish(nil)
			return nil
		}
		c.mu.Unlock()

		select {
		case <-c.wakeCh:
		case <-haltCh:
			c.cancel(errSACKCancelled)
			return c.err
		}
	}
}

// admit puts as many queued boxes on the wire as the window allows, one at a
// time. It runs only in the driver goroutine, so a blocking send is safe. A
// send error aborts admission and is returned to fail the transfer.
func (c *sackController) admit() error {
	for {
		c.mu.Lock()
		if c.finished || c.next >= c.total || len(c.inflight) >= c.window {
			c.mu.Unlock()
			return nil
		}
		i := c.next
		c.next++
		c.inflight[i] = true
		c.mu.Unlock()

		if err := c.sender.send(i); err != nil {
			return err
		}
	}
}

// boxAcked marks a write box acknowledged. It is boxDone with no payload.
func (c *sackController) boxAcked(index int) {
	c.boxDone(index, nil)
}

// boxDone marks box `index` complete, recording its payload (nil for writes,
// the decrypted box data for reads), and wakes the driver to admit the next
// queued box. Duplicate or post-teardown completions are ignored.
func (c *sackController) boxDone(index int, data []byte) {
	c.mu.Lock()
	if c.finished || !c.inflight[index] {
		c.mu.Unlock()
		return
	}
	delete(c.inflight, index)
	c.results[index] = data
	c.completed++
	c.mu.Unlock()
	c.wake()
}

// payload concatenates the per-box results in box order. Meaningful only
// after run() returns nil; used by the read path to reassemble the payload.
func (c *sackController) payload() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []byte
	for _, r := range c.results {
		out = append(out, r...)
	}
	return out
}

// boxFailed terminates the whole transfer with err when a box fails
// unrecoverably (a fatal reply the ARQ machinery surfaces). A nil error is
// normalised to the generic cancellation error.
func (c *sackController) boxFailed(index int, err error) {
	if err == nil {
		err = errSACKCancelled
	}
	c.cancel(err)
}

// cancel tears the transfer down with err, cancelling every still-in-flight
// box exactly once and waking the driver. Idempotent: a second cancel (or a
// cancel racing completion) is a no-op.
func (c *sackController) cancel(err error) {
	c.mu.Lock()
	if c.finished {
		c.mu.Unlock()
		return
	}
	inflight := make([]int, 0, len(c.inflight))
	for i := range c.inflight {
		inflight = append(inflight, i)
	}
	c.finished = true
	c.err = err
	c.mu.Unlock()

	c.wake()
	for _, i := range inflight {
		c.sender.cancel(i)
	}
}

// finish records a terminal result (used for success) exactly once.
func (c *sackController) finish(err error) {
	c.mu.Lock()
	if !c.finished {
		c.finished = true
		c.err = err
	}
	c.mu.Unlock()
}

// wake pulses the driver's wake channel without blocking.
func (c *sackController) wake() {
	select {
	case c.wakeCh <- struct{}{}:
	default:
	}
}
