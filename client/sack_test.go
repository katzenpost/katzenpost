// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package client

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/client/thin"
)

// fakeSender is a boxSender for unit tests. It records each send and cancel
// on a buffered channel so a test can synchronise on them, and lets the test
// inject a send-time failure for chosen indices.
type fakeSender struct {
	sends   chan int
	cancels chan int

	mu      sync.Mutex
	sendErr map[int]error
}

func newFakeSender(capacity int) *fakeSender {
	return &fakeSender{
		sends:   make(chan int, capacity),
		cancels: make(chan int, capacity),
		sendErr: make(map[int]error),
	}
}

func (f *fakeSender) failSend(index int, err error) {
	f.mu.Lock()
	f.sendErr[index] = err
	f.mu.Unlock()
}

func (f *fakeSender) send(index int) error {
	f.mu.Lock()
	err := f.sendErr[index]
	f.mu.Unlock()
	f.sends <- index
	return err
}

func (f *fakeSender) cancel(index int) {
	f.cancels <- index
}

const sackTestTimeout = 2 * time.Second

// nextSend returns the index of the next box put on the wire, failing the
// test if none arrives promptly.
func (f *fakeSender) nextSend(t *testing.T) int {
	t.Helper()
	select {
	case i := <-f.sends:
		return i
	case <-time.After(sackTestTimeout):
		t.Fatal("timed out waiting for a send")
		return -1
	}
}

// collectSends gathers exactly n sends and returns the set of indices.
func (f *fakeSender) collectSends(t *testing.T, n int) map[int]bool {
	t.Helper()
	got := make(map[int]bool, n)
	for k := 0; k < n; k++ {
		got[f.nextSend(t)] = true
	}
	return got
}

// assertNoSend fails if any further send occurs within a short grace period,
// proving the window is holding boxes back.
func (f *fakeSender) assertNoSend(t *testing.T) {
	t.Helper()
	select {
	case i := <-f.sends:
		t.Fatalf("unexpected send of box %d", i)
	case <-time.After(100 * time.Millisecond):
	}
}

// runAsync starts the controller in its own goroutine and returns a channel
// carrying its terminal error.
func runAsync(c *sackController, haltCh <-chan interface{}) <-chan error {
	res := make(chan error, 1)
	go func() { res <- c.run(haltCh) }()
	return res
}

func waitResult(t *testing.T, res <-chan error) error {
	t.Helper()
	select {
	case err := <-res:
		return err
	case <-time.After(sackTestTimeout):
		t.Fatal("timed out waiting for run() to return")
		return nil
	}
}

func assertStillRunning(t *testing.T, res <-chan error) {
	t.Helper()
	select {
	case err := <-res:
		t.Fatalf("run() returned early with %v", err)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestComputeSACKWindow(t *testing.T) {
	// Default docker rates: LambdaP=0.001, Mu=0.005, forward NrHops=5
	// (gateway + 3 mix layers + service). Round-trip N_hops = 2*5-1 = 9.
	// W* = ceil(0.001/0.005 * 9) + 1 = ceil(1.8) + 1 = 3. Matches the
	// measured knee (window 1 -> 0.21 boxes/s, window >=4 -> 0.29 plateau).
	require.Equal(t, 3, computeSACKWindow(0.001, 0.005, 5))

	// A ten-fold faster send rate widens the pipe proportionally.
	require.Equal(t, 19, computeSACKWindow(0.01, 0.005, 5))

	// A larger topology (5 mix layers, forward NrHops=7) needs a bit more.
	require.Equal(t, 4, computeSACKWindow(0.001, 0.005, 7))

	// Degenerate or missing parameters fall back to stop-and-wait (1).
	require.Equal(t, sackFallbackWindow, computeSACKWindow(0, 0.005, 5))
	require.Equal(t, sackFallbackWindow, computeSACKWindow(0.001, 0, 5))
	require.Equal(t, sackFallbackWindow, computeSACKWindow(0.001, 0.005, 0))
}

func TestSACKErrorToCode(t *testing.T) {
	require.Equal(t, uint8(thin.ThinClientSuccess), sackErrorToCode(nil))
	require.Equal(t, uint8(thin.ThinClientErrorStartResendingCancelled), sackErrorToCode(errSACKCancelled))
	require.Equal(t, uint8(thin.ThinClientErrorStartResendingCancelled), sackErrorToCode(fmt.Errorf("wrapped: %w", errSACKCancelled)))
	require.Equal(t, uint8(thin.ThinClientErrorInternalError), sackErrorToCode(errors.New("some other error")))
	require.Equal(t, uint8(7), sackErrorToCode(&sackBoxError{code: 7}))
}

func TestSACKZeroTotal(t *testing.T) {
	f := newFakeSender(4)
	c := newSACKController(f, 0, 4)
	require.NoError(t, c.run(nil))
	f.assertNoSend(t)
}

func TestSACKSingleBox(t *testing.T) {
	f := newFakeSender(4)
	c := newSACKController(f, 1, 1)
	res := runAsync(c, nil)

	require.Equal(t, 0, f.nextSend(t))
	f.assertNoSend(t)
	c.boxAcked(0)

	require.NoError(t, waitResult(t, res))
}

func TestSACKWindowLargerThanTotalClamps(t *testing.T) {
	f := newFakeSender(8)
	c := newSACKController(f, 3, 99)
	res := runAsync(c, nil)

	// All three boxes admitted at once because the window clamps to total.
	require.Equal(t, map[int]bool{0: true, 1: true, 2: true}, f.collectSends(t, 3))
	f.assertNoSend(t)

	c.boxAcked(0)
	c.boxAcked(1)
	c.boxAcked(2)
	require.NoError(t, waitResult(t, res))
}

func TestSACKWindowBoundsInflight(t *testing.T) {
	const total, window = 5, 2
	f := newFakeSender(16)
	c := newSACKController(f, total, window)
	res := runAsync(c, nil)

	// Only `window` boxes in flight up front.
	require.Equal(t, map[int]bool{0: true, 1: true}, f.collectSends(t, 2))
	f.assertNoSend(t)

	// Each ack admits exactly one more box, never exceeding the window,
	// until the queue drains.
	c.boxAcked(0)
	require.Equal(t, 2, f.nextSend(t))
	f.assertNoSend(t)

	c.boxAcked(1)
	require.Equal(t, 3, f.nextSend(t))
	f.assertNoSend(t)

	c.boxAcked(2)
	require.Equal(t, 4, f.nextSend(t))
	f.assertNoSend(t)

	// Last two acks drain the queue; no further sends.
	c.boxAcked(3)
	f.assertNoSend(t)
	assertStillRunning(t, res)
	c.boxAcked(4)
	require.NoError(t, waitResult(t, res))
}

func TestSACKOutOfOrderAcks(t *testing.T) {
	f := newFakeSender(8)
	c := newSACKController(f, 4, 4)
	res := runAsync(c, nil)

	require.Equal(t, map[int]bool{0: true, 1: true, 2: true, 3: true}, f.collectSends(t, 4))
	for _, i := range []int{3, 1, 2, 0} {
		c.boxAcked(i)
	}
	require.NoError(t, waitResult(t, res))
}

func TestSACKDuplicateAckIgnored(t *testing.T) {
	f := newFakeSender(8)
	c := newSACKController(f, 2, 2)
	res := runAsync(c, nil)
	f.collectSends(t, 2)

	c.boxAcked(0)
	c.boxAcked(0) // duplicate must not count toward completion
	assertStillRunning(t, res)

	c.boxAcked(1)
	require.NoError(t, waitResult(t, res))
}

func TestSACKSendErrorFailsTransfer(t *testing.T) {
	sendErr := errors.New("compose failed")
	f := newFakeSender(16)
	c := newSACKController(f, 4, 2)
	f.failSend(1, sendErr)
	res := runAsync(c, nil)

	// Box 0 and 1 are admitted; send(1) fails, tearing the transfer down.
	require.ErrorIs(t, waitResult(t, res), sendErr)

	// Both still-in-flight boxes are cancelled exactly once. Cancellation
	// order is unspecified (map iteration), so drain both and compare sets.
	cancelled := map[int]bool{}
	for k := 0; k < 2; k++ {
		select {
		case i := <-f.cancels:
			cancelled[i] = true
		case <-time.After(sackTestTimeout):
			t.Fatal("timed out waiting for cancellation")
		}
	}
	require.Equal(t, map[int]bool{0: true, 1: true}, cancelled)
}

func TestSACKExternalCancel(t *testing.T) {
	f := newFakeSender(16)
	c := newSACKController(f, 4, 2)
	res := runAsync(c, nil)
	require.Equal(t, map[int]bool{0: true, 1: true}, f.collectSends(t, 2))

	c.cancel(errSACKCancelled)
	require.ErrorIs(t, waitResult(t, res), errSACKCancelled)

	cancelled := map[int]bool{}
	for k := 0; k < 2; k++ {
		select {
		case i := <-f.cancels:
			cancelled[i] = true
		case <-time.After(sackTestTimeout):
			t.Fatal("timed out waiting for cancellation")
		}
	}
	require.Equal(t, map[int]bool{0: true, 1: true}, cancelled)
}

func TestSACKDoubleCancelIdempotent(t *testing.T) {
	f := newFakeSender(16)
	c := newSACKController(f, 4, 2)
	res := runAsync(c, nil)
	f.collectSends(t, 2)

	c.cancel(errSACKCancelled)
	require.ErrorIs(t, waitResult(t, res), errSACKCancelled)

	// A second cancel after teardown is a no-op: no further cancellations
	// and the recorded error is unchanged.
	c.cancel(errors.New("ignored"))
	require.ErrorIs(t, c.err, errSACKCancelled)
}

func TestSACKBoxFailedNilErrorBecomesCancelled(t *testing.T) {
	f := newFakeSender(16)
	c := newSACKController(f, 4, 2)
	res := runAsync(c, nil)
	f.collectSends(t, 2)

	// A failure reported with a nil error still terminates the transfer,
	// surfacing the generic cancellation error rather than a nil error.
	c.boxFailed(0, nil)
	require.ErrorIs(t, waitResult(t, res), errSACKCancelled)
}

func TestSACKHaltTearsDown(t *testing.T) {
	f := newFakeSender(16)
	haltCh := make(chan interface{})
	c := newSACKController(f, 4, 2)
	res := runAsync(c, haltCh)
	f.collectSends(t, 2)

	close(haltCh)
	require.ErrorIs(t, waitResult(t, res), errSACKCancelled)
}

// TestSACKDrainPipeline exercises a longer transfer with a small window,
// acking the oldest in-flight box each step, and asserts the window stays
// full until the tail and every box is sent exactly once.
// TestSACKReadReassembly checks that per-box payloads completed out of order
// are reassembled in box order, as the read path requires.
func TestSACKReadReassembly(t *testing.T) {
	f := newFakeSender(16)
	c := newSACKController(f, 4, 2)
	res := runAsync(c, nil)
	require.Equal(t, map[int]bool{0: true, 1: true}, f.collectSends(t, 2))

	data := map[int][]byte{0: []byte("AAA"), 1: []byte("BB"), 2: []byte("CCCC"), 3: []byte("D")}

	c.boxDone(0, data[0])
	require.Equal(t, 2, f.nextSend(t))
	c.boxDone(2, data[2])
	require.Equal(t, 3, f.nextSend(t))
	c.boxDone(3, data[3])
	c.boxDone(1, data[1])

	require.NoError(t, waitResult(t, res))
	require.Equal(t, []byte("AAABBCCCCD"), c.payload())
}

func TestSACKDrainPipeline(t *testing.T) {
	const total, window = 20, 4
	f := newFakeSender(64)
	c := newSACKController(f, total, window)
	res := runAsync(c, nil)

	inflight := []int{}
	for _, i := range []int{0, 1, 2, 3} {
		require.Equal(t, i, f.nextSend(t))
		inflight = append(inflight, i)
	}

	sent := map[int]bool{0: true, 1: true, 2: true, 3: true}
	next := 4
	for next < total {
		oldest := inflight[0]
		inflight = inflight[1:]
		c.boxAcked(oldest)

		got := f.nextSend(t)
		require.Equal(t, next, got, "boxes must be admitted in order")
		require.False(t, sent[got], "box %d sent twice", got)
		sent[got] = true
		inflight = append(inflight, got)
		next++
		require.LessOrEqual(t, len(inflight), window)
	}

	// Drain the final window.
	for _, i := range inflight {
		c.boxAcked(i)
	}
	require.NoError(t, waitResult(t, res))
	require.Len(t, sent, total)
}
