// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package voucher_router

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/katzenpost/pigeonservice/common"
)

// ErrMessageTooLarge reports a message larger than one box.
var ErrMessageTooLarge = errors.New("pigeonservice: message larger than one box")

// Conn is a two-way Pigeonhole connection: a stream this side writes and a
// stream the peer writes. Send and Recv may be called concurrently.
type Conn struct {
	ph           common.Pigeonhole
	pollInterval time.Duration
	writeCap     *bacap.WriteCap
	readCap      *bacap.ReadCap

	// sendMu and recvMu serialize sends and receives; they are held for
	// as long as an operation takes.
	sendMu sync.Mutex
	recvMu sync.Mutex

	// mu guards the state below and is only held briefly.
	mu       sync.Mutex
	writeIdx *bacap.MessageBoxIndex
	readIdx  *bacap.MessageBoxIndex
	sent     []sentBox
	changed  func(*Conn)
}

type sentBox struct {
	Index     []byte
	Plaintext []byte
	At        time.Time
}

func newConn(ph common.Pigeonhole, wc *bacap.WriteCap, widx *bacap.MessageBoxIndex, rc *bacap.ReadCap, ridx *bacap.MessageBoxIndex, pollInterval time.Duration) *Conn {
	return &Conn{
		ph:           ph,
		pollInterval: pollInterval,
		writeCap:     wc,
		writeIdx:     widx,
		readCap:      rc,
		readIdx:      ridx,
	}
}

// OnChange sets a function called after every Send, Recv and Refresh. A
// Conn restored from state saved before a Send would write that Send's box
// again, where the write is a silent no-op, so state must be saved after
// each one.
func (c *Conn) OnChange(f func(*Conn)) {
	c.mu.Lock()
	c.changed = f
	c.mu.Unlock()
}

func (c *Conn) notify() {
	c.mu.Lock()
	f := c.changed
	c.mu.Unlock()
	if f != nil {
		f(c)
	}
}

// Send writes msg to the next box of this side's stream.
func (c *Conn) Send(ctx context.Context, msg []byte) error {
	if len(msg) == 0 {
		return errors.New("pigeonservice: empty message")
	}
	if len(msg) > c.ph.MaxPlaintext() {
		return ErrMessageTooLarge
	}
	c.sendMu.Lock()
	defer c.sendMu.Unlock()

	c.mu.Lock()
	idx := c.writeIdx
	c.mu.Unlock()
	next, err := common.WriteRetry(ctx, c.ph, c.writeCap, idx, msg)
	if err != nil {
		return err
	}
	idxBytes, err := idx.MarshalBinary()
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.sent = append(c.sent, sentBox{Index: idxBytes, Plaintext: append([]byte(nil), msg...), At: time.Now()})
	c.writeIdx = next
	c.mu.Unlock()
	c.notify()
	return nil
}

// Recv waits for the peer's next message. Tombstoned boxes are skipped.
func (c *Conn) Recv(ctx context.Context) ([]byte, error) {
	c.recvMu.Lock()
	defer c.recvMu.Unlock()
	for {
		c.mu.Lock()
		idx := c.readIdx
		c.mu.Unlock()
		msg, next, err := common.ReadWait(ctx, c.ph, c.readCap, idx, c.pollInterval)
		if err != nil && !errors.Is(err, common.ErrTombstone) {
			return nil, err
		}
		c.mu.Lock()
		c.readIdx = next
		c.mu.Unlock()
		c.notify()
		if err == nil {
			return msg, nil
		}
	}
}

// Retained returns how many sent boxes Refresh still rewrites.
func (c *Conn) Retained() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.sent)
}

// Refresh rewrites every box sent within retention, restoring any a replica
// has garbage-collected, and forgets older ones. Pigeonhole keeps a box for
// one to two replica epochs; calling Refresh once a replica epoch keeps a
// box readable for as long as retention allows. Rewrites are idempotent.
func (c *Conn) Refresh(ctx context.Context, retention time.Duration) error {
	cutoff := time.Now().Add(-retention)
	c.mu.Lock()
	kept := make([]sentBox, 0, len(c.sent))
	for _, b := range c.sent {
		if !b.At.Before(cutoff) {
			kept = append(kept, b)
		}
	}
	c.sent = kept
	c.mu.Unlock()
	c.notify()

	for _, b := range kept {
		idx, err := bacap.NewEmptyMessageBoxIndexFromBytes(b.Index)
		if err != nil {
			return err
		}
		if _, err := c.ph.Write(ctx, c.writeCap, idx, b.Plaintext); err != nil {
			return err
		}
	}
	return nil
}

// ConnState is a Conn's persistent state.
type ConnState struct {
	WriteCap []byte
	WriteIdx []byte
	ReadCap  []byte
	ReadIdx  []byte
	Sent     []sentBox
}

// State returns the Conn's state for persistence.
func (c *Conn) State() (*ConnState, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := &ConnState{Sent: append([]sentBox(nil), c.sent...)}
	var err error
	if s.WriteCap, err = c.writeCap.MarshalBinary(); err != nil {
		return nil, err
	}
	if s.WriteIdx, err = c.writeIdx.MarshalBinary(); err != nil {
		return nil, err
	}
	if s.ReadCap, err = c.readCap.MarshalBinary(); err != nil {
		return nil, err
	}
	if s.ReadIdx, err = c.readIdx.MarshalBinary(); err != nil {
		return nil, err
	}
	return s, nil
}

// RestoreConn rebuilds a Conn from its persistent state.
func RestoreConn(ph common.Pigeonhole, s *ConnState, pollInterval time.Duration) (*Conn, error) {
	wc, err := bacap.NewWriteCapFromBytes(s.WriteCap)
	if err != nil {
		return nil, err
	}
	widx, err := bacap.NewEmptyMessageBoxIndexFromBytes(s.WriteIdx)
	if err != nil {
		return nil, err
	}
	rc, err := bacap.ReadCapFromBytes(s.ReadCap)
	if err != nil {
		return nil, err
	}
	ridx, err := bacap.NewEmptyMessageBoxIndexFromBytes(s.ReadIdx)
	if err != nil {
		return nil, err
	}
	c := newConn(ph, wc, widx, rc, ridx, pollInterval)
	c.sent = append([]sentBox(nil), s.Sent...)
	return c, nil
}
